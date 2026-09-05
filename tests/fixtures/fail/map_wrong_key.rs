use std::collections::BTreeMap;

use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(map)]
    values: BTreeMap<u32, String>,
}

fn main() {}
