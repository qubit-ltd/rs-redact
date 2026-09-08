// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Direct hidden projections must reject missing serialization scopes safely.

#![cfg(all(feature = "derive", feature = "serde"))]

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::domain::internal::RedactSerializeSource;

/// A nested value whose source must never appear in a scope error.
#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct Credential {
    /// The sensitive source payload.
    #[redact(level = "secret")]
    password: String,
}

/// Neither Some nor None can bypass the required policy and budget scope.
#[test]
fn test_optional_projection_without_scope_returns_a_value_free_error() {
    let policy = RedactionPolicy::standard();
    for value in [
        None,
        Some(Credential {
            password: "raw-secret".into(),
        }),
    ] {
        let projection = value.redacted_fields(&policy);
        let error = serde_json::to_string(&projection).expect_err("missing scope must return Err");
        assert!(error.to_string().contains("active redaction scope"));
        assert!(!error.to_string().contains("raw-secret"));
    }
}

/// Empty and nonempty vectors require a scope before structural admission.
#[test]
fn test_vector_projection_without_scope_returns_a_value_free_error() {
    let policy = RedactionPolicy::standard();
    for value in [
        Vec::new(),
        vec![Credential {
            password: "raw-secret".into(),
        }],
    ] {
        let projection = value.redacted_fields(&policy);
        let error = serde_json::to_string(&projection).expect_err("missing scope must return Err");
        assert!(error.to_string().contains("active redaction scope"));
        assert!(!error.to_string().contains("raw-secret"));
    }
}

/// Ordinary views supply the scope for empty and populated containers.
#[test]
fn test_container_views_establish_the_required_scope() {
    let redactor = Redactor::standard();
    for value in [
        None,
        Some(Credential {
            password: "raw-secret".into(),
        }),
    ] {
        let output = serde_json::to_value(redactor.redact_view(&value)).expect("scoped option");
        if value.is_some() {
            assert_eq!(output["password"], "<redacted>");
        } else {
            assert!(output.is_null());
        }
    }
    for value in [
        Vec::new(),
        vec![Credential {
            password: "raw-secret".into(),
        }],
    ] {
        let output = serde_json::to_value(redactor.redact_view(&value)).expect("scoped vector");
        assert_eq!(output.as_array().expect("array shape").len(), value.len());
        if !value.is_empty() {
            assert_eq!(output[0]["password"], "<redacted>");
        }
    }
}
