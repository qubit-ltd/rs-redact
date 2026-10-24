// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Debug, Redact)]
#[redact(serde)]
struct Borrowed<'a, T> {
    value: &'a T,
}

fn main() {
    let source = String::from("source");
    let value = Borrowed { value: &source };
    let redactor = Redactor::standard();
    let _ = redactor.redact_text(&value);
    let _ = serde_json::to_value(redactor.redact_view(&value));
    let _ = serde_json::to_value(&value);
}
