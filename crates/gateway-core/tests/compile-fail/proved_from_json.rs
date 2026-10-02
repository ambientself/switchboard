// A proved value cannot be read from JSON: reading is not verifying.

use gateway_core::{Principal, Proved};

fn read(text: &str) -> Proved<Principal> {
    serde_json::from_str(text).unwrap()
}

fn main() {}
