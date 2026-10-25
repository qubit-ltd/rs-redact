// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Debug)]
struct TextOnly;

#[derive(Debug, Redact)]
struct Concrete {
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<TextOnly>,
}

fn main() {
    let value = Concrete { value: Some(TextOnly) };
    let redactor = Redactor::standard();
    let text = redactor.redact_text(&value);
    assert!(text.complete_text().is_ok());
    let _ = redactor.to_json(&value);
}
