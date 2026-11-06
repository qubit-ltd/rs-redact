// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

pub use runtime::__qubit_redact_serde;
pub use runtime::__qubit_redact_serde_optional;
pub use runtime::Redact;
pub use runtime::RedactionCompletion;
pub use runtime::RedactionPolicy;
pub use runtime::RedactionWriter;
pub use runtime::Redactor;
pub use runtime::Sensitivity;
pub use runtime::domain;

#[derive(qubit_redact_derive::Redact)]
struct Record {
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let record = Record {
        password: "raw-secret".into(),
    };
    let output = Redactor::standard().redact_text(&record);
    assert!(output.text().as_str().contains("<redacted>"));
    assert!(!output.text().as_str().contains("raw-secret"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}
