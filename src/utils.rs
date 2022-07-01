use std::fs::copy;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::{fs, io};

pub fn secretcli_command(args: Vec<&str>, chain_id: String, node: String) -> String {
    let output = Command::new("secretcli")
        .args(args)
        .arg("--chain-id")
        .arg(chain_id)
        .arg("--node")
        .arg(node)
        .output()
        .expect("failed to execute secretcli command");
    String::from_utf8(output.stdout).unwrap()
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
    sha256::digest_bytes(&bytes)
}

pub fn find_wasm_file(tmp_dir: &Path) -> Option<PathBuf> {
    let target_wasm_path = tmp_dir.join("contract.wasm");
    if target_wasm_path.exists() {
        return Some(tmp_dir.join("contract.wasm"));
    }
    let output_dir = tmp_dir.join("target/wasm32-unknown-unknown/release/");
    if !output_dir.exists() {
        return None;
    }
    for entry in fs::read_dir(output_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().unwrap() == "wasm" {
            copy(path, target_wasm_path.clone()).unwrap();
            return Some(target_wasm_path);
        }
    }
    None
}
