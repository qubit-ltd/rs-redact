// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Debug)]
struct External(String);

fn is_empty(value: &External) -> bool {
    value.0.is_empty()
}

fn encode<S: serde::Serializer>(value: &External, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.0)
}

#[derive(Debug, Redact)]
#[redact(serde)]
struct Record {
    #[serde(serialize_with = "encode", skip_serializing_if = "is_empty")]
    value: External,
}

fn main() {
    let record = Record {
        value: External("visible".to_owned()),
    };
    let _ = Redactor::standard().redact_text(&record);
    let _ = serde_json::to_value(Redactor::standard().redact_view(&record));
}
