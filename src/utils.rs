use std::fs::{remove_dir_all, remove_file};
use std::process::{self, Output};
use std::path::{Path, PathBuf};
use std::{fs, io};
use bson::doc;
use mongodb::options::CountOptions;
use mongodb::{Client, Collection};

use crate::constants::DB_ERROR_EXIT_CODE;
use crate::types::{CodeDatabaseDocument, DatabaseDocument};

pub fn get_command_stdout(output: io::Result<Output>) -> Result<String, String> {
    if output.is_err() {
        return Err(format!("Command Error: {}", output.unwrap_err()));
    }
    let out = output.unwrap();
    if !out.status.success() {
        println!("Failed Command StdOut: {}", &out.status);

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        println!("Failed Command StdOut: {}", stdout);

        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        println!("Failed Command StdErr: {}", stderr);

        return Err(stderr);
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn get_command_stderr(output: io::Result<Output>) -> Result<String, String> {
    if output.is_err() {
        return Err(format!("{}", output.unwrap_err()));
    }
    let out = output.unwrap();
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&out.stderr).to_string())
}

pub fn wasm_file_hash(file_path: PathBuf) -> String {
    let bytes = fs::read(file_path).expect("Failed to read file");
    sha256::digest(&bytes)
}

pub async fn db_contains_existing_verification(
    client: &Client,
    repo: &str,
    commit_hash: &str,
) -> bool {
    let collection: Collection<DatabaseDocument> = client.default_database().unwrap().collection("contract_verifications");

    let filter = doc! {
        "repo": repo,
        "commit_hash": commit_hash,
    };

    let options = CountOptions::builder().build();

    let result = collection.count_documents(filter, options).await;

    if result.is_err() {
        print!("Failed to check DB for existing verification: {:?}", result.unwrap());
        process::exit(DB_ERROR_EXIT_CODE);
    }

    if result.unwrap() > 0u64 {
        return true;
    }
    else {
        return false;
    }
}


pub async fn db_contains_code_hash(
    client: &Client,
    code_hash: &str,
) -> bool {
    let collection: Collection<CodeDatabaseDocument> = client.default_database().unwrap().collection("codes");

    let filter = doc! {
        "codeHash": code_hash,
    };

    let options = CountOptions::builder().build();

    let result = collection.count_documents(filter, options).await;

    if result.is_err() {
        print!("Failed to check DB for resulting code hash: {:?}", result.unwrap());
        process::exit(DB_ERROR_EXIT_CODE);
    }

    if result.unwrap() > 0u64 {
        return true;
    }
    else {
        return false;
    }
}

pub fn clean_artifacts(tmp_dir: &Path) {
    println!("Cleaning up build artifacts");
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
        let result = remove_dir_all(&target_dir_path);
        if result.is_err() {
            println!("Failed to remove target directory")
        }
    }
}

pub fn clean_all(tmp_dir: &Path) {
    println!("Deleting temp directory");

    if tmp_dir.exists() {
        let result = remove_dir_all(&tmp_dir);
        if result.is_err() {
            println!("Failed to remove temp directory!")
        }
    }
}