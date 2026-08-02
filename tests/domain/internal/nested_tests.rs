// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for explicit recursive domain-object redaction.

use qubit_redact::{MaskPolicy, Redact, RedactionPolicy, Sensitivity};
use qubit_redact_derive::Redact;

/// Sensitive nested credential.
#[derive(Debug, Redact)]
struct Credential {
    /// Secret token.
    #[redact(level = "secret")]
    token: String,
}

/// Object covering every supported nested container.
#[derive(Redact)]
struct Session {
    /// Direct nested object.
    #[redact(nested)]
    primary: Credential,
    /// Optional boxed nested object.
    #[redact(nested)]
    backup: Option<Box<Credential>>,
    /// Sequence of nested objects.
    #[redact(nested)]
    history: Vec<Credential>,
    /// Deliberately unmarked control field.
    ordinary: Credential,
}

/// Verifies every nested container receives the same explicit policy.
#[test]
fn test_nested_uses_the_same_explicit_policy_for_every_container() {
    let policy = RedactionPolicy::builder()
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[strict]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the fixed replacement is valid");
    let session = Session {
        primary: Credential {
            token: "one".to_owned(),
        },
        backup: Some(Box::new(Credential {
            token: "two".to_owned(),
        })),
        history: vec![Credential {
            token: "three".to_owned(),
        }],
        ordinary: Credential {
            token: "raw-ordinary".to_owned(),
        },
    };

    let rendered = format!("{:?}", session.redacted_with(&policy));

    assert_eq!(rendered.matches("[strict]").count(), 3);
    assert!(!rendered.contains("one"));
    assert!(!rendered.contains("two"));
    assert!(!rendered.contains("three"));
    assert!(rendered.contains("raw-ordinary"));
}

/// Verifies absent and empty nested containers preserve their shape.
#[test]
fn test_nested_preserves_absent_and_empty_containers() {
    let session = Session {
        primary: Credential {
            token: "one".to_owned(),
        },
        backup: None,
        history: Vec::new(),
        ordinary: Credential {
            token: "raw-ordinary".to_owned(),
        },
    };

    let rendered = format!("{:?}", session.redacted());

    assert!(rendered.contains("backup: None"));
    assert!(rendered.contains("history: []"));
}
