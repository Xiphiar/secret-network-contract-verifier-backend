use std::env;
use std::env::set_current_dir;
use std::error::Error;
use std::fmt::Write as _;
use std::fs::{remove_dir_all, remove_file};
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::time::SystemTime;
use clap::Parser;
use bson::{doc, Binary};
use mongodb::options::{ClientOptions, FindOneAndUpdateOptions, ResolverConfig};
use mongodb::{Client, Collection};
use sudo::escalate_if_needed;
use types::DatabaseDocument;
use utils::{get_code_hash, get_command_stdout};
use crate::utils::wasm_file_hash;
use base64::prelude::*;

mod types;
mod utils;

#[derive(Parser, Debug, Clone, PartialEq)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(long, value_parser)]
    code_id: u16,

    #[clap(long, value_parser, help = "Git url of the code")]
    repo: String,

    #[clap(short, long, value_parser, default_value = "HEAD")]
    commit: String,

    #[clap(long, value_parser, default_value = "secret-4")]
    chain_id: String,

    #[clap(
        short,
        long,
        value_parser,
        default_value = "https://secret.api.trivium.network:1317"
    )]
    lcd: String,

    #[clap(short, long, value_parser)]
    require_sudo: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let optimizer_images: Vec<&str> = vec![
        "enigmampc/secret-contract-optimizer:1.0.10",
        "enigmampc/secret-contract-optimizer:1.0.9",
        "enigmampc/secret-contract-optimizer:1.0.8",

        // 1.0.6 is the same as 1.0.7 but with support for arm -- not needed for now
        "enigmampc/secret-contract-optimizer:1.0.7",

        "enigmampc/secret-contract-optimizer:1.0.5",

        // 1.0.2-1.0.3 run the same version of rust as the one used in 1.0.4, so they're redundant
        "enigmampc/secret-contract-optimizer:1.0.4",

         // 1.0.0-1.0.1 run the same version of rust
        "enigmampc/secret-contract-optimizer:1.0.1",
    ];

    let client_uri = env::var("MONGODB_URI").expect("You must set the MONGODB_URI environment var!");
    println!("{}", client_uri);

    let args: Args = Args::parse();

    if args.require_sudo {
        escalate_if_needed().expect("Failed to escalate privileges");
    }

    let code_id = args.code_id;
    let repo = args.clone().repo;
    let mut commit_hash = args.clone().commit;
    let now = SystemTime::now();

    // A Client is needed to connect to MongoDB:
    // An extra line of code to work around a DNS issue on Windows:
    let options = ClientOptions::parse_with_resolver_config(&client_uri, ResolverConfig::cloudflare()).await?;
    let client = Client::with_options(options)?;
    if client.default_database().is_none() {
        println!("Default database not defined in connection string");
        return Ok(())
    }

    client.list_database_names(None, None).await?;
    let default_db = client.default_database().unwrap();
    let db_name = default_db.name();
    println!("Database: {}", db_name);

    println!("Checking if already verified...");
    // TODO
    println!("TODO");

    let unix_time = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let tmp_dir = env::temp_dir().join(format!(
        "contract-verifier-{}-{}-{}",
        code_id, commit_hash, unix_time
    ));
    let clone_repo_out = clone_repo(tmp_dir.clone(), repo.clone(), commit_hash.clone());
    if commit_hash == "HEAD" {
        commit_hash = get_commit_hash(tmp_dir.clone()).unwrap();
    }
    println!("Commit Hash: {}", commit_hash);
    if commit_hash.is_empty() {
        panic!("Failed to get commit hash");
    }

    match clone_repo_out {
        Ok(output) => {
            println!("Clone Output: {}", output);
        }
        Err(e) => {
            println!("Clone error: {}", e);
            return Ok(());
        }
    }

    println!("Getting uploaded code hash...");
    let code_hash = get_code_hash(&code_id, &args.lcd).await?;
    println!("Code hash to check against: {}", code_hash);
    set_current_dir(&tmp_dir).unwrap();
    for optimizer_image in optimizer_images {
        let result_hash = compile_with_optimizer(&tmp_dir, optimizer_image);
        if result_hash == code_hash.clone() {
            println!("Code hash matches when compiling with {}", optimizer_image);

            // Get code.zip binary data
            let zip_path = format!("{}/code.zip", tmp_dir.to_string_lossy());
            let bytes = std::fs::read(&zip_path).unwrap();
            let base64 = BASE64_STANDARD.encode(bytes);
            let binary = Binary::from_base64(base64, None)?;

            // This function will exit the process
            commit_result_to_database(
                &client,
                args.chain_id.clone(),
                code_id,
                repo.clone(),
                commit_hash.clone(),
                result_hash,
                optimizer_image.to_string(),
                true,
                Some(binary),
            ).await;
            process::exit(0);
        } else {
            commit_result_to_database(
                &client,
                args.chain_id.clone(),
                code_id, repo.clone(),
                commit_hash.clone(),
                result_hash,
                optimizer_image.to_string(),
                false,
                None,
            ).await;
        }
    }
    // Exit with non-0 code if none of the images produced a matching hash
    process::exit(127);
}

async fn commit_result_to_database(
    client: &Client,
    chain_id: String,
    code_id: u16,
    repo: String,
    commit_hash: String,
    result_hash: String,
    builder: String,
    verified: bool,
    zip_binary: Option<Binary>,
) {
    // let collection: Collection<DatabaseDocument> = client.default_database().unwrap().collection::<DatabaseDocument>("contract_verifications");
    let collection: Collection<DatabaseDocument> = client.default_database().unwrap().collection("contract_verifications");

    let filter = doc! {
        "chain_id": chain_id.clone(),
        "code_id": code_id.clone().to_string(),
        "repo": repo.clone(),
        "commit_hash": commit_hash.clone(),
        "builder": builder.clone(),
    };

    // let new_doc = DatabaseDocument {
    //     chain_id,
    //     code_id: code_id.to_string(),
    //     repo,
    //     commit_hash,
    //     result_hash,
    //     builder,
    //     verified
    // };

    let new_doc = doc! {
        "chain_id": chain_id.clone(),
        "code_id": code_id.to_string(),
        "repo": repo,
        "commit_hash": commit_hash,
        "result_hash": result_hash,
        "builder": builder,
        "verified": verified,
        "code_zip": zip_binary,
    };

    let update = doc! {
        "$set": new_doc,
    };

    let options = FindOneAndUpdateOptions::builder().upsert(true).build();

    let result = collection.find_one_and_update(filter, update, options).await;
    // let result = collection.insert_one(new_doc, None).await;

    if result.is_err() {
        print!("Failed to add to DB: {:?}", result.unwrap());
        process::exit(127);
    }
}

fn clean(tmp_dir: &Path) {
    println!("Cleaning up");
    let wasm_file_path = tmp_dir.join("contract.wasm");
    let gzip_file_path = tmp_dir.join("contract.wasm.gz");
    let target_dir_path = tmp_dir.join("target");
    if wasm_file_path.exists() {
        println!("Removing wasm file {}", wasm_file_path.display());
        remove_file(&wasm_file_path).unwrap();
    }
    if gzip_file_path.exists() {
        println!("Removing gzip file {}", gzip_file_path.display());
        remove_file(&gzip_file_path).unwrap();
    }
    if target_dir_path.exists() {
        println!("Removing target dir {}", target_dir_path.display());
        remove_dir_all(&target_dir_path).unwrap_or_default();
    }
}

fn compile_with_optimizer(
    tmp_dir: &PathBuf,
    optimizer_image: &str,
) -> String {
    println!("Attempting to compile with {}", optimizer_image);

    let docker_out = Command::new("docker")
        .arg("run")
        .arg("--rm")
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
        return format!("BUILD_FAIL");
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
    clean(tmp_dir);
    wasm_hash
}

async fn get_code_hash(code_id: &u16, lcd: &str) -> Result<String, Error> {
    let url = format!("{}/compute/v1beta1/code_hash/by_code_id/{}", lcd, code_id);
    let resp = reqwest::get(url)
        .await?
        .json::<LcdCodeHashByCodeIdResponse>()
        .await?;
    
    Ok(resp.code_hash)
}

fn clone_repo(path: PathBuf, repo: String, commit_hash: String) -> Result<String, String> {
    let mut clone = Command::new("git");
    clone.arg("clone").arg(repo.clone()).arg(path.clone());
    let mut stderr = String::new();
    writeln!(stderr, "Cloning {}", repo).unwrap();
    stderr.push_str(&(utils::get_command_stderr(clone.output())?));
    if commit_hash != "HEAD" {
        let mut reset = Command::new("git");
        reset
            .current_dir(&path)
            .arg("reset")
            .arg("--hard")
            .arg(commit_hash);
        stderr.push_str(&(utils::get_command_stderr(reset.output())?));
    }
    let _ = zip_repo(path)?;
    Ok(stderr)
}

fn zip_repo(path: PathBuf) -> Result<String, String> {
    let path_string = path.to_string_lossy();
    let files = format!("{}/*", path_string);
    let zip_file = format!("{}/code.zip", path_string);
    let cmd = format!("zip -r {} {}", zip_file, files);

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
