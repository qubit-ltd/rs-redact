// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Map-level generated tokens remain hygienic when `Some` and `None` are shadowed.

use std::collections::BTreeMap;

use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

enum LocalOption<T> {
    Some(T),
    None,
}
use LocalOption::None;
use LocalOption::Some;

#[derive(Redact)]
struct Maps {
    #[redact(map_key_level = "secret")]
    keys: BTreeMap<String, String>,
    #[redact(map_key_level = "secret", map_value_level = "secret")]
    both: BTreeMap<String, String>,
}

fn main() {
    let _ = Some(1_u8);
    let _: LocalOption<u8> = None;
    let source = Maps {
        keys: BTreeMap::from([("raw-key-a".to_owned(), "visible-value".to_owned())]),
        both: BTreeMap::from([("raw-key-b".to_owned(), "raw-value".to_owned())]),
    };
    let redactor = Redactor::standard();
    let output = redactor.redact_text(&source);
    assert!(!output.text().as_str().contains("raw-key-"));
    assert!(!output.text().as_str().contains("raw-value"));
    assert!(output.text().as_str().contains("visible-value"));
    let serialized = serde_json::to_value(redactor.redact_view(&source)).expect("view serialization");
    let text = serialized.to_string();
    assert!(!text.contains("raw-key-"));
    assert!(!text.contains("raw-value"));
    assert!(text.contains("visible-value"));
}
