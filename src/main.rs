use std::env;
use std::env::set_current_dir;
use std::error::Error;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{self};
use std::process::Command;
use std::time::SystemTime;
use clap::Parser;
use bson::{doc, Binary};
use constants::{ALREADY_VERIFIED_EXIT_CODE, DB_ERROR_EXIT_CODE, DOCKER_ERROR_EXIT_CODE, NO_MATCH_EXIT_CODE, SECRET_OPTIMIZER_IMAGES};
use mongodb::options::{ClientOptions, FindOneAndUpdateOptions, ResolverConfig};
use mongodb::{Client, Collection};
// use sudo::escalate_if_needed;
use types::DatabaseDocument;
use utils::{clean_all, clean_artifacts, db_contains_code_hash, db_contains_existing_verification, get_command_stdout};
use crate::utils::wasm_file_hash;
use base64::prelude::*;
use users::get_current_uid;

mod types;
mod utils;
mod constants;

#[derive(Parser, Debug, Clone, PartialEq)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(long, value_parser, help = "Git url of the code")]
    repo: String,

    #[clap(short, long, value_parser, default_value = "HEAD")]
    commit: String,

    #[clap(long, value_parser, help = "Specific optimizer version to use (e.g. 1.0.7)")]
    optimizer: Option<String>,

    // #[clap(short, long, value_parser)]
    // require_sudo: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client_uri = env::var("MONGODB_URI").expect("You must set the MONGODB_URI environment var!");
    println!("{}", client_uri);

    let args: Args = Args::parse();

    // if args.require_sudo {
    //     escalate_if_needed().expect("Failed to escalate privileges");
    // }

    let repo = args.clone().repo;
    let mut commit_hash = args.clone().commit;
    let now = SystemTime::now();
    let uid = get_current_uid();

    // A Client is needed to connect to MongoDB:
    // An extra line of code to work around a DNS issue on Windows:
    let options = ClientOptions::parse_with_resolver_config(&client_uri, ResolverConfig::cloudflare()).await?;
    let client = Client::with_options(options)?;
    if client.default_database().is_none() {
        println!("Default database not defined in connection string");
        return Ok(())
    }

    // Connect to MongoDB
    client.list_database_names(None, None).await?;
    let default_db = client.default_database().unwrap();
    let db_name = default_db.name();
    println!("Database: {}", db_name);

    // Clone repo to /tmp
    let unix_time = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let tmp_dir = env::temp_dir().join(format!(
        "contract-verifier-{}-{}",
        commit_hash, unix_time
    ));
    let clone_repo_out = clone_repo(tmp_dir.clone(), repo.clone(), commit_hash.clone());
    match clone_repo_out {
        Ok(output) => {
            println!("Clone Output: {}", output);
        }
        Err(e) => {
            println!("Clone error: {}", e);
            return Ok(());
        }
    }

    // Get commit hash
    commit_hash = get_commit_hash(tmp_dir.clone()).unwrap();
    println!("Commit Hash: {}", commit_hash);
    if commit_hash.is_empty() {
        panic!("Failed to get commit hash");
    }

    set_current_dir(&tmp_dir).unwrap();

    // Check if already verified
    println!("Checking if already verified...");
    let already_verified = db_contains_existing_verification(&client, &repo, &commit_hash).await;
    if already_verified {
        println!("Code has already been verified!");
        clean_all(&tmp_dir);
        process::exit(ALREADY_VERIFIED_EXIT_CODE)
    }

    // Determine which optimizer images to use
    let optimizer_images: Vec<String> = if let Some(version) = args.optimizer {
        let image = format!("enigmampc/secret-contract-optimizer:{}", version);
        println!("Using specified optimizer version: {}", image);
        vec![image]
    } else {
        println!("No specific optimizer specified. Trying all available optimizers...");
        SECRET_OPTIMIZER_IMAGES.iter().map(|&s| s.to_string()).collect()
    };

    // Compile with selected optimizer image(s)
    for optimizer_image in optimizer_images {
        let result_hash = compile_with_optimizer(&tmp_dir, &optimizer_image, &uid.to_string());
        let matches_code_in_db = db_contains_code_hash(&client, &result_hash).await;
        if matches_code_in_db {
            println!("Found a matching code hash when compiling with {}", optimizer_image);

            // Get code.zip binary data
            let zip_path = format!("{}/code.zip", tmp_dir.to_string_lossy());
            let bytes = std::fs::read(&zip_path).unwrap();
            let base64 = BASE64_STANDARD.encode(bytes);
            let binary = Binary::from_base64(base64, None)?;

            // This function will exit the process
            commit_result_to_database(
                &client,
                repo.clone(),
                commit_hash.clone(),
                result_hash,
                optimizer_image,
                Some(binary),
            ).await;

            clean_all(&tmp_dir);
            process::exit(0);
        } else {
            println!("Resulting code hash did NOT match any codes in the DB.\n")
        }
    }
    // Exit with non-0 code if none of the images produced a matching hash
    process::exit(NO_MATCH_EXIT_CODE);
}

async fn commit_result_to_database(
    client: &Client,
    repo: String,
    commit_hash: String,
    result_hash: String,
    builder: String,
    zip_binary: Option<Binary>,
) {
    let collection: Collection<DatabaseDocument> = client.default_database().unwrap().collection("contract_verifications");

    let filter = doc! {
        "repo": repo.clone(),
        "commit_hash": commit_hash.clone(),
        "builder": builder.clone(),
    };

    let new_doc = doc! {
        "repo": repo,
        "commit_hash": commit_hash,
        "result_hash": result_hash,
        "builder": builder,
        "code_zip": zip_binary,
    };

    let update = doc! {
        "$set": new_doc,
    };

    let options = FindOneAndUpdateOptions::builder().upsert(true).build();

    let result = collection.find_one_and_update(filter, update, options).await;

    if result.is_err() {
        print!("Failed to add to DB: {:?}", result.unwrap());
        process::exit(DB_ERROR_EXIT_CODE);
    }
}

fn compile_with_optimizer(
    tmp_dir: &PathBuf,
    optimizer_image: &str,
    uid: &str,
) -> String {
    println!("Attempting to compile with {}", optimizer_image);

    let docker_out = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("-u")
        .arg(uid)
        .arg("--volume")
        .arg(format!("{}:/contract", tmp_dir.display()))
        .arg("--volume")
        .arg(format!(
            "{}:/optimizer",
            env::current_dir().unwrap().display()
        ))
        // .stdout(Stdio::inherit())
        // .stderr(Stdio::inherit())
        .arg(optimizer_image)
        .output()
        .expect("failed to execute process");

    if !docker_out.status.success() {
        let std_err = String::from_utf8_lossy(&docker_out.stderr).to_string();

        if docker_out.status.code() == Some(125) {
            print!("Enocuntered an error starting the docker image: {}", std_err);
            process::exit(DOCKER_ERROR_EXIT_CODE);
        }

        print!("Docker command failed: {}", std_err);
        process::exit(DOCKER_ERROR_EXIT_CODE);
        
        // return format!("BUILD_FAIL");
    }

    let mut wasm_hash = "BUILD_FAIL".to_string();

    let gzip_file = tmp_dir.join("contract.wasm.gz");
    let gunzip_command = Command::new("gunzip")
        .arg(&gzip_file)
        .current_dir(&tmp_dir)
        .output()
        .expect("failed to execute process");
    if gunzip_command.status.success() {
        let wasm_file = tmp_dir.join("contract.wasm");
        if wasm_file.exists() {
            wasm_hash = wasm_file_hash(wasm_file);
            println!("Resulting Hash: {}", wasm_hash);
        }
    }
    clean_artifacts(tmp_dir);
    wasm_hash
}

fn clone_repo(path: PathBuf, repo: String, commit: String) -> Result<String, String> {
    // Clone repo to temp directory
    println!("Cloning repo {} into directory {}", repo, path.display());
    let mut clone = Command::new("git");
    clone.arg("clone").arg(repo.clone()).arg(path.clone());
    let mut stderr = String::new();
    writeln!(stderr, "Cloning {}", repo).unwrap();
    stderr.push_str(&(utils::get_command_stderr(clone.output())?));

    // if commit_hash != "HEAD" {
    //     let mut reset = Command::new("git");
    //     reset
    //         .current_dir(&path)
    //         .arg("reset")
    //         .arg("--hard")
    //         .arg(commit_hash);
    //     stderr.push_str(&(utils::get_command_stderr(reset.output())?));
    // }

    // Checkout commit hash/branch
    println!("Checking out commit {}", commit);
    let mut checkout = Command::new("git");
    checkout
        .arg("checkout")
        .arg(commit);
    stderr.push_str(&(utils::get_command_stderr(checkout.output())?));

    let _ = zip_repo(path)?;
    Ok(stderr)
}

fn zip_repo(path: PathBuf) -> Result<String, String> {
    let path_string = path.to_string_lossy();
    let files = format!("{}/*", path_string);
    let zip_file = format!("{}/code.zip", path_string);
    let cmd = format!("zip -r {} {}", zip_file, files);
    println!("Zipping repo to {}", zip_file);

    let mut zip = Command::new("bash");
    zip.arg("-c")
       .arg(cmd);

    let output = zip.output();
    let stdout = get_command_stdout(output)?;

    Ok(stdout)
}

fn get_commit_hash(path: PathBuf) -> Result<String, String> {
    let mut commit_hash = Command::new("git");
    commit_hash.arg("rev-parse").arg("HEAD").current_dir(&path);
    Ok(utils::get_command_stdout(commit_hash.output())?.trim().to_string())
}
