use std::env;
use std::env::set_current_dir;
use std::fmt::Write as _;
use std::fs::{remove_dir_all, remove_file};
use std::path::{Path, PathBuf};
use std::process;
use std::process::{Command, Stdio};
use std::time::SystemTime;

use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sudo::escalate_if_needed;

use crate::utils::{secretcli_command, secretcli_execute, wasm_file_hash};

mod utils;

/// Simple program to greet a person
#[derive(Parser, Debug, Clone, PartialEq)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, value_parser)]
    code_id: u16,

    #[clap(long, value_parser, help = "Git url of the code")]
    repo: String,

    #[clap(short, long, value_parser, default_value = "HEAD")]
    commit: String,

    #[clap(short, long, value_parser)]
    database_contract: String,

    #[clap(long, value_parser, default_value = "secret-4")]
    chain_id: String,

    #[clap(
        short,
        long,
        value_parser,
        default_value = "https://scrt-validator.digiline.io:26657/"
    )]
    node: String,

    #[clap(short, long, value_parser)]
    require_sudo: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct ContractInfo {
    address: String,
    code_id: u16,
    creator: String,
    label: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum DatabaseMsg {
    WriteResult {
        code_id: u16,
        repo: String,
        commit_hash: String,
        method: String,
        verified: bool,
    },
}

fn main() {
    let optimizer_images: Vec<&str> = vec![
        "enigmampc/secret-contract-optimizer:1.0.7",
        // 1.0.6 is the same as 1.0.7 but with support for arm -- not needed for now
        "enigmampc/secret-contract-optimizer:1.0.5",
        "enigmampc/secret-contract-optimizer:1.0.4",
        // 1.0.0-1.0.3 run the same version of rust as the one used in 1.0.4, so they're redundant
    ];

    let args: Args = Args::parse();

    if args.require_sudo {
        escalate_if_needed().expect("Failed to escalate privileges");
    }

    let code_id = args.code_id;
    let repo = args.clone().repo;
    let mut commit_hash = args.clone().commit;
    let database_contract = args.clone().database_contract;
    let now = SystemTime::now();

    Command::new("secretcli")
        .args(vec!["config", "node", &args.node])
        .output()
        .expect("Failed to run secretcli config node");
    Command::new("secretcli")
        .args(vec!["config", "chain-id", &args.chain_id])
        .output()
        .expect("Failed to run secretcli config chain-id");

    let check_json = json!({
        "check_code_id": {
            "code_id": code_id,
        },
    })
    .to_string();

    let verification_result = secretcli_command(
        vec!["query", "compute", "query", &database_contract, &check_json],
        true,
    );

    if !verification_result.starts_with("Error: query result: encrypted: Not verified") {
        println!("Contract is already verified");
        println!("{}", verification_result);
        process::exit(0);
    }

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
    match clone_repo_out {
        Ok(output) => {
            println!("{}", output);
        }
        Err(e) => {
            println!("{}", e);
            return;
        }
    }
    let code_hash = get_code_hash(&code_id);
    println!("Code hash to check against: {}", code_hash);
    set_current_dir(&tmp_dir).unwrap();
    for optimizer_image in optimizer_images {
        if check_if_matches_code_hash_with_optimizer(&tmp_dir, code_hash.clone(), optimizer_image) {
            println!("Code hash matches when compiling with {}", optimizer_image);
            contract_verification_successful(
                code_id,
                repo.clone(),
                commit_hash.clone(),
                optimizer_image,
                database_contract.clone(),
            );
        }
    }
    unsuccessful_contract_verification(code_id, repo, commit_hash, database_contract);
}

fn unsuccessful_contract_verification(
    code_id: u16,
    repo: String,
    commit_hash: String,
    database_contract: String,
) {
    commit_result_to_database(code_id, repo, commit_hash, "", database_contract, false);
    process::exit(127);
}

fn contract_verification_successful(
    code_id: u16,
    repo: String,
    commit_hash: String,
    method: &str,
    database_contract: String,
) {
    commit_result_to_database(code_id, repo, commit_hash, method, database_contract, true);
    process::exit(0);
}

fn commit_result_to_database(
    code_id: u16,
    repo: String,
    commit_hash: String,
    method: &str,
    database_contract: String,
    verified: bool,
) {
    let json = json!(DatabaseMsg::WriteResult {
        code_id,
        repo,
        commit_hash,
        method: method.to_string(),
        verified,
    });
    let out = secretcli_execute(vec![
        "tx",
        "compute",
        "execute",
        &database_contract,
        &json.to_string(),
    ]);
    println!("{}", out);
}

fn clean(tmp_dir: &Path) {
    println!("Cleaning up");
    let wasm_file_path = tmp_dir.join("contract.wasm");
    let gzip_file_path = tmp_dir.join("contract.wasm.gz");
    let target_dir_path = tmp_dir.join("target");
    if wasm_file_path.exists() {
        remove_file(&wasm_file_path).unwrap();
    }
    if gzip_file_path.exists() {
        remove_file(&gzip_file_path).unwrap();
    }
    if target_dir_path.exists() {
        remove_dir_all(&target_dir_path).unwrap();
    }
}

fn check_if_matches_code_hash_with_optimizer(
    tmp_dir: &PathBuf,
    code_hash: String,
    optimizer_image: &str,
) -> bool {
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
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .arg(optimizer_image)
        .output()
        .expect("failed to execute process");
    if !docker_out.status.success() {
        return false;
    }
    let gzip_file = tmp_dir.join("contract.wasm.gz");
    let gunzip_command = Command::new("gunzip")
        .arg(&gzip_file)
        .current_dir(&tmp_dir)
        .output()
        .expect("failed to execute process");
    if gunzip_command.status.success() {
        let wasm_file = tmp_dir.join("contract.wasm");
        if wasm_file.exists() {
            let wasm_hash = wasm_file_hash(wasm_file);
            println!(
                "Checking if code hash {} matches wasm file hash {}",
                code_hash, wasm_hash
            );
            if wasm_hash == code_hash {
                return true;
            }
        }
    }
    clean(tmp_dir);
    false
}

fn get_code_hash(code_id: &u16) -> String {
    let contracts_with_code_id_str = secretcli_command(
        vec![
            "query",
            "compute",
            "list-contract-by-code",
            &code_id.to_string(),
        ],
        false,
    );
    let contracts_with_code_id: Vec<ContractInfo> =
        serde_json::from_str(&contracts_with_code_id_str).unwrap();
    secretcli_command(
        vec![
            "query",
            "compute",
            "contract-hash",
            &contracts_with_code_id[0].address,
        ],
        false,
    )[2..]
        .to_string()
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
    Ok(stderr)
}
fn get_commit_hash(path: PathBuf) -> Result<String, String> {
    let mut commit_hash = Command::new("git");
    commit_hash.arg("rev-parse").arg("HEAD").current_dir(&path);
    Ok(utils::get_command_stderr(commit_hash.output())?)
}
