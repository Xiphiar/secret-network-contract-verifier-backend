use bson::Binary;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DatabaseDocument {
    pub chain_id: String,
    pub code_id: String,
    pub repo: String,
    pub commit_hash: String,
    pub result_hash: String,
    pub builder: String,
    pub verified: bool,
    pub code_zip: Option<Binary>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LcdCodeHashByCodeIdResponse {
    pub code_hash: String
}