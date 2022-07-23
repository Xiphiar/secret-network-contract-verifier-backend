use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::{env, path::PathBuf};
use std::{fs, io};

pub fn secretcli_command(args: Vec<&str>, stderr: bool) -> String {
    let output = Command::new("secretcli")
        .args(args)
        .output()
        .expect("failed to execute secretcli command");
    if stderr {
        return String::from_utf8_lossy(&output.stderr).to_string();
    }
    String::from_utf8(output.stdout).unwrap()
}

pub fn secretcli_execute(args: Vec<&str>) -> String {
    let mut command = Command::new("secretcli")
        .args(args)
        .arg("--from")
        .arg("Verifier")
        .arg("-y")
        .arg("--gas")
        .arg("100000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let command_stdin = command.stdin.as_mut().unwrap();

    command_stdin
        .write_all(
            format!(
                "{}\n",
                env::var("VERIFIER_PASSWORD").unwrap_or("verifier".to_string())
            )
            .as_bytes(),
        )
        .unwrap();

    drop(command_stdin);

    let out = command.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap()
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
