use bson::Binary;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DatabaseDocument {
    pub repo: String,
    pub commit_hash: String,
    pub result_hash: String,
    pub builder: String,
    pub code_zip: Option<Binary>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct CodeDatabaseDocument {
    pub codeHash: String,
}