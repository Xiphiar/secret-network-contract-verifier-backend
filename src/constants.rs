pub const ALREADY_VERIFIED_EXIT_CODE: i32 = 124;
pub const DB_ERROR_EXIT_CODE: i32 = 125;
pub const DOCKER_ERROR_EXIT_CODE: i32 = 126;
pub const NO_MATCH_EXIT_CODE: i32 = 127;

pub const SECRET_OPTIMIZER_IMAGES: [&'static str; 7] = [
    "enigmampc/secret-contract-optimizer:1.0.10",
    "enigmampc/secret-contract-optimizer:1.0.9",
    "enigmampc/secret-contract-optimizer:1.0.8",

    // 1.0.7 is the same as 1.0.6 but with support for arm, so 1.0.6 is redundant
    "enigmampc/secret-contract-optimizer:1.0.7",

    "enigmampc/secret-contract-optimizer:1.0.5",

    // 1.0.2-1.0.3 run the same version of rust as the one used in 1.0.4, so they're redundant
    "enigmampc/secret-contract-optimizer:1.0.4",

     // 1.0.0-1.0.1 run the same version of rust, so 1.0.0 is redundant
    "enigmampc/secret-contract-optimizer:1.0.1",
];