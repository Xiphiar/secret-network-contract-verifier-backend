use std::process::Output;
use std::path::PathBuf;
use std::{fs, io};
use reqwest::Error;

use crate::types::LcdCodeHashByCodeIdResponse;

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

pub async fn get_code_hash(code_id: &u16, lcd: &str) -> Result<String, Error> {
    let url = format!("{}/compute/v1beta1/code_hash/by_code_id/{}", lcd, code_id);
    let resp = reqwest::get(url)
        .await?
        .json::<LcdCodeHashByCodeIdResponse>()
        .await?;
    
    Ok(resp.code_hash)
}