// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for every enum variant shape.

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

/// Enum combining named, tuple, and unit variants.
#[derive(Redact)]
enum Event {
    /// Named variant with a sensitive field.
    Named {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple variant with a sensitive and skipped field.
    Tuple(#[redact(level = "secret")] String, #[redact(skip)] String),
    /// Unit variant.
    Ready,
}

/// Exercises complete safe output for every supported variant shape.
fn main() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2).max_collection_items(1).max_depth(1);
        })
        .expect("the fixture redaction policy limits should be valid")
        .build()
        .expect("the fixture redaction policy should be valid");

    let named = Event::Named {
        secret: "raw-named".to_owned(),
    };
    let tuple = Event::Tuple("raw-tuple".to_owned(), "skipped".to_owned());
    assert_eq!(
        Redactor::new(policy.clone()).redact(&named).text().as_str(),
        r#"Named { secret: "<redacted>" }"#,
    );
    assert_eq!(
        Redactor::new(policy.clone()).redact(&tuple).text().as_str(),
        r#"Tuple("<redacted>")"#,
    );
    assert!(
        Redactor::new(policy)
            .redact(&Event::Ready)
            .text()
            .as_str()
            .contains("Ready")
    );
}
