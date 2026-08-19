// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::RedactionCompletion;
use qubit_redact::Redactor;

/// Verifies that environment redaction masks a password value.
#[test]
fn test_redactor_redact_env_masks_password_value() {
    let output = Redactor::standard().redact_env("PASSWORD", "raw");

    assert_eq!(output.text().as_str(), "PASSWORD=<redacted>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

#[test]
fn test_redactor_redact_env_pairs_publishes_one_safe_collection() {
    let output = Redactor::standard().redact_env_pairs([
        (OsStr::new("REGION"), OsStr::new("ap-east-1")),
        (OsStr::new("PASSWORD"), OsStr::new("raw-secret")),
    ]);

    assert!(output.text().as_str().contains("REGION=ap-east-1"));
    assert!(!output.text().as_str().contains("raw-secret"));
}
