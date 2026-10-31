// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "derive")]

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Redact)]
struct RecursiveNode {
    name: String,
    next: Option<Box<Self>>,
}

impl std::fmt::Debug for RecursiveNode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ordinary-child")
    }
}

#[derive(Redact)]
struct ExplicitUnmarkedNode {
    name: String,
    #[redact(unmarked)]
    next: Option<Box<Self>>,
}

impl std::fmt::Debug for ExplicitUnmarkedNode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ordinary-child")
    }
}

#[derive(Redact)]
struct OrdinaryField {
    value: String,
}

#[derive(Redact)]
struct ExplicitOrdinaryField {
    #[redact(unmarked)]
    value: String,
}

#[test]
fn test_explicit_unmarked_recursive_field_uses_ordinary_debug() {
    let nested = RecursiveNode {
        name: "child".into(),
        next: None,
    };
    let automatic = RecursiveNode {
        name: "root".into(),
        next: Some(Box::new(nested)),
    };
    let nested = ExplicitUnmarkedNode {
        name: "child".into(),
        next: None,
    };
    let explicit = ExplicitUnmarkedNode {
        name: "root".into(),
        next: Some(Box::new(nested)),
    };

    let automatic_output = Redactor::standard().redact_text(&automatic);
    let explicit_output = Redactor::standard().redact_text(&explicit);
    assert!(!automatic_output.text().as_str().contains("ordinary-child"));
    assert!(explicit_output.text().as_str().contains("ordinary-child"));
}

#[test]
fn test_explicit_unmarked_plain_field_uses_ordinary_output() {
    let ordinary = OrdinaryField {
        value: "ordinary".into(),
    };
    let explicit = ExplicitOrdinaryField {
        value: "ordinary".into(),
    };
    assert!(
        Redactor::standard()
            .redact_text(&ordinary)
            .text()
            .as_str()
            .contains("ordinary")
    );
    assert!(
        Redactor::standard()
            .redact_text(&explicit)
            .text()
            .as_str()
            .contains("ordinary")
    );
}
