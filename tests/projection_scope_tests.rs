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
use qubit_redact::domain::internal::RedactSerialize;
use qubit_redact::domain::internal::RedactSerializeScope;
use qubit_redact::domain::internal::RedactSerializeSource;

/// A nested value whose source must never appear in a scope error.
#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct Credential {
    /// The sensitive source payload.
    #[redact(level = "secret")]
    password: String,
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
enum CredentialState {
    Empty,
    Present {
        #[redact(level = "secret")]
        password: String,
    },
}

/// The legacy hook installs its explicit policy when called without a scope.
#[test]
fn test_legacy_hook_without_scope_uses_its_explicit_policy() {
    let value = Credential {
        password: "raw-secret".into(),
    };
    let output = value
        .serialize_redacted(serde_json::value::Serializer, &RedactionPolicy::standard())
        .expect("direct legacy hook serialization");
    assert_eq!(output["password"], "<redacted>");
}

/// The explicit hook policy is scoped for one call and restores the caller's
/// scope.
#[test]
fn test_legacy_hook_policy_overrides_and_restores_outer_scope() {
    let outer_policy = RedactionPolicy::disabled();
    let _scope = RedactSerializeScope::new(&outer_policy);
    let value = Credential {
        password: "raw-secret".into(),
    };
    let standard = value
        .serialize_redacted(serde_json::value::Serializer, &RedactionPolicy::standard())
        .expect("explicit standard policy");
    assert_eq!(standard["password"], "<redacted>");

    let disabled = value
        .serialize_redacted(serde_json::value::Serializer, &outer_policy)
        .expect("explicit disabled policy");
    assert_eq!(disabled["password"], "raw-secret");
    assert!(
        qubit_redact::domain::internal::current_policy()
            .expect("outer policy restored")
            .is_disabled()
    );
}

/// Bare struct, populated enum, and unit enum projections return errors safely.
#[test]
fn test_bare_projections_without_scope_return_value_free_errors() {
    let policy = RedactionPolicy::standard();
    let credential = Credential {
        password: "raw-secret".into(),
    };
    let struct_error = serde_json::to_string(&credential.redacted_fields(&policy))
        .expect_err("bare struct projection must require a scope");
    assert!(struct_error.to_string().contains("active redaction scope"));
    assert!(!struct_error.to_string().contains("raw-secret"));

    for value in [
        CredentialState::Empty,
        CredentialState::Present {
            password: "raw-secret".into(),
        },
    ] {
        let error = serde_json::to_string(&value.redacted_fields(&policy))
            .expect_err("bare enum projection must require a scope");
        assert!(error.to_string().contains("active redaction scope"));
        assert!(!error.to_string().contains("raw-secret"));
    }
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
