// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for crate-level exports.

use std::ffi::OsStr;

use qubit_redact::RedactedText;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

/// Verifies the intended top-level redaction types remain publicly exported.
#[test]
fn test_lib_exports_public_api() {
    let policy = RedactionPolicy::default();
    let redactor = Redactor::new(policy);

    let field = redactor.redact_field("name", "Ada");
    let _: &RedactedText = field.text();
    assert_eq!(field.text().as_str(), "Ada");

    let argv = [ArgvItem::plain(OsStr::new("client"))];
    assert!(
        redactor
            .redact_argv(argv)
            .text()
            .as_str()
            .contains("client")
    );
    assert!(
        redactor
            .redact_env("HOME", "/tmp")
            .text()
            .as_str()
            .contains("HOME")
    );

    let output = redactor.text_composer().literal(" context").finish();
    assert_eq!(output.text().as_str(), " context");
    let mut batch = redactor.batch();
    let item = batch.redact_field("name", "Ada");
    assert_eq!(
        batch
            .finish()
            .resolve(item)
            .expect("same batch")
            .text()
            .as_str(),
        "Ada"
    );
}
