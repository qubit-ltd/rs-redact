// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Passing fixture for redacted serialization.

use qubit_redact::Redact;
use qubit_redact_derive::Redact;
use serde::Serialize;

/// Serializable record using a supported rename.
#[derive(Redact, Serialize)]
#[redact(serde)]
struct Record {
    /// Renamed plain field.
    #[serde(rename = "wire_name")]
    name: String,
    /// Sensitive field.
    #[redact(level = "secret")]
    secret: String,
}

/// Serializes the redacted view.
fn main() {
    let value = Record {
        name: "Alice".to_owned(),
        secret: "raw".to_owned(),
    };
    let _ = serde_json::to_string(&value.redacted()).expect("serialization succeeds");
}
