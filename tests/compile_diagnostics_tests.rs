// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regressions distinguishing compiler API rejection from infrastructure
//! failure.

mod support;

use serde_json::Value;
use serde_json::json;
use support::compile_diagnostics::source_error_matches;

/// Models Cargo's stable diagnostic envelope for one fixture-source error.
fn source_error() -> Value {
    json!({
        "reason": "compiler-message",
        "target": { "src_path": "/tmp/fixture/src/main.rs" },
        "message": {
            "level": "error",
            "code": { "code": "E0599" },
            "message": "no method named `inspect_uri` found",
            "spans": [{ "is_primary": true, "file_name": "src/main.rs" }]
        }
    })
}

/// Accepts the intended source error and rejects a different API name.
#[test]
fn test_matches_only_the_requested_source_error() {
    let bytes = source_error().to_string();
    assert!(source_error_matches(bytes.as_bytes(), "inspect_uri", Some("E0599")));
    assert!(!source_error_matches(
        bytes.as_bytes(),
        "redact_http_url",
        Some("E0599")
    ));
}

/// A package name containing the API name cannot make Cargo failure pass.
#[test]
fn test_rejects_cargo_errors_containing_the_expected_name() {
    for text in [
        "error: no matching package found; required by qubit-redact-map-api",
        "error: failed to run rustc for qubit-redact-feature-gate-inspect_uri",
        r#"{"reason":"build-finished","success":false}"#,
        "invalid JSON inspect_uri",
    ] {
        assert!(!source_error_matches(text.as_bytes(), "inspect_uri", Some("E0599")));
        assert!(!source_error_matches(text.as_bytes(), "map", None));
    }
}

/// Warnings, missing error codes and dependency spans are not API rejection.
#[test]
fn test_rejects_non_source_or_non_error_compiler_messages() {
    for (pointer, replacement) in [
        ("/reason", json!("compiler-artifact")),
        ("/target/src_path", json!("/dependency/src/lib.rs")),
        ("/message/level", json!("warning")),
        ("/message/code", Value::Null),
        ("/message/spans/0/is_primary", json!(false)),
        ("/message/spans/0/file_name", json!("/dependency/src/lib.rs")),
    ] {
        let mut event = source_error();
        *event.pointer_mut(pointer).expect("fixture pointer exists") = replacement;
        assert!(
            !source_error_matches(event.to_string().as_bytes(), "inspect_uri", Some("E0599")),
            "{pointer}"
        );
    }
}

/// Some rustc diagnostics have no code; their source/error envelope is
/// required.
#[test]
fn test_accepts_an_uncoded_source_error_only_when_no_code_is_required() {
    let mut event = source_error();
    event["message"]["code"] = Value::Null;
    let bytes = event.to_string();
    assert!(source_error_matches(bytes.as_bytes(), "inspect_uri", None));
    assert!(!source_error_matches(bytes.as_bytes(), "inspect_uri", Some("E0599")));
}
