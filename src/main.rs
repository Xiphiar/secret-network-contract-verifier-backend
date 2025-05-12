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
use crate::constants::{ALREADY_VERIFIED_EXIT_CODE, DB_ERROR_EXIT_CODE, DOCKER_ERROR_EXIT_CODE, INVALID_COMMIT_EXIT_CODE, NO_MATCH_EXIT_CODE, SECRET_OPTIMIZER_IMAGES, NO_WASM_FILE_EXIT_CODE};
use mongodb::options::{ClientOptions, FindOneAndUpdateOptions, ResolverConfig};
use mongodb::{Client, Collection};
// use sudo::escalate_if_needed;
use types::DatabaseDocument;
use utils::{clean_all, clean_artifacts, db_contains_code_hash, db_contains_existing_verification, get_command_stdout};
use crate::utils::wasm_file_hash;
use base64::prelude::*;
use users::get_current_uid;
use semver::Version;

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
        let parsed_version = Version::parse(&version).unwrap();

        let mut image = "enigmampc/secret-contract-optimizer".to_string();
        // Versions greater than 1.0.10 use ghcr.io/scrtlabs/secret-contract-optimizer
        if parsed_version > Version::parse("1.0.10")? {
            image = "ghcr.io/scrtlabs/secret-contract-optimizer".to_string();
        }

        let optimizer = format!("{}:{}", image, version);
        println!("Using specified optimizer: {}", optimizer);
        vec![optimizer]
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

    // Check default location first
    let default_gzip_file = tmp_dir.join("contract.wasm.gz");
    let mut gzip_file_path = default_gzip_file.clone();
    
    if !default_gzip_file.exists() {
        // Check for wasm.gz file in optimized-wasm directory
        let optimized_dir = tmp_dir.join("optimized-wasm");
        
        if optimized_dir.exists() && optimized_dir.is_dir() {
            let mut found_wasm_gz = false;
            
            // Find the first .wasm.gz file in the optimized-wasm directory
            if let Ok(entries) = std::fs::read_dir(&optimized_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("gz") {
                        if let Some(filename) = path.file_name().and_then(|name| name.to_str()) {
                            if filename.ends_with(".wasm.gz") {
                                gzip_file_path = path;
                                found_wasm_gz = true;
                                println!("Found optimized WASM file at: {}", gzip_file_path.display());
                                break;
                            }
                        }
                    }
                }
            }
            
            if !found_wasm_gz {
                println!("No .wasm.gz file found in optimized-wasm directory");
                // process::exit(NO_WASM_FILE_EXIT_CODE);
            }
        } else {
            println!("Neither contract.wasm.gz nor optimized-wasm directory found");
            // process::exit(NO_WASM_FILE_EXIT_CODE);
        }
    }

    // Use the found gzip file
    let gunzip_command = Command::new("gunzip")
        .arg(&gzip_file_path)
        .current_dir(&tmp_dir)
        .output()
        .expect("failed to execute process");
    if gunzip_command.status.success() {
        let wasm_file = gzip_file_path.with_extension("");
        if wasm_file.exists() {
            wasm_hash = wasm_file_hash(wasm_file);
            println!("Resulting Hash: {}", wasm_hash);
        } else {
            println!("Wasm file does not exist at path {}", wasm_file.display())
        }
    } else {
        println!("Failed to unzip file at {}", gzip_file_path.display())
    }
    clean_artifacts(tmp_dir);
    wasm_hash
}

fn clone_repo(path: PathBuf, repo: String, commit: String) -> Result<String, String> {
    println!("Cloning repo {} into directory {}", repo, path.display());

    // Clone repo to temp directory
    let mut clone = Command::new("git");
    clone.arg("clone").arg(repo.clone()).arg(path.clone());
    let mut stderr = String::new();
    writeln!(stderr, "Cloning {}", repo).unwrap();
    stderr.push_str(&(utils::get_command_stderr(clone.output())?));

    // Validate commit exists
    let mut validate_and_check = |ref_to_validate: &str| {
        let mut cmd = Command::new("git");
        cmd.current_dir(&path)
            .arg("rev-parse")
            .arg("--verify")
            .arg(ref_to_validate);

        cmd.output().map_or(false, |output| output.status.success())
    };

    let mut is_valid_reference = validate_and_check(&commit);

    if !is_valid_reference {
        let origin_prefixed_commit = format!("origin/{}", commit);
        is_valid_reference = validate_and_check(&origin_prefixed_commit);
    }
    
    if !is_valid_reference {
        println!("Invalid commit, branch or tag: {}", commit);
        process::exit(INVALID_COMMIT_EXIT_CODE);
    }

    // Checkout commit hash/branch
    println!("Checking out commit {}", commit);
    let mut checkout = Command::new("git");
    checkout
        .current_dir(&path)
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
