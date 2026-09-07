// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(debug, display, serde)]
struct Credential<'a> {
    #[redact(level = "secret")]
    number: &'a str,
}

#[derive(Redact)]
#[redact(debug, display, serde)]
struct PersonInfo<'a> {
    #[redact(nested)]
    credential: Option<Credential<'a>>,
}

#[derive(Redact)]
#[redact(debug, display, serde)]
struct Person<'a> {
    #[redact(nested)]
    credential: Option<Credential<'a>>,
    guardians: Option<Vec<PersonInfo<'a>>>,
}

fn encode_local<'a>(number: &'a str) -> serde_json::Value {
    let person = Person {
        credential: Some(Credential { number }),
        guardians: Some(vec![PersonInfo {
            credential: Some(Credential { number }),
        }]),
    };
    serde_json::to_value(&person).expect("borrowed nested source should serialize")
}

fn main() {
    let local = String::from("raw-credential");
    let value = encode_local(&local);
    assert_ne!(value["credential"]["number"], "raw-credential");
    assert_ne!(value["guardians"][0]["credential"]["number"], "raw-credential");
}
