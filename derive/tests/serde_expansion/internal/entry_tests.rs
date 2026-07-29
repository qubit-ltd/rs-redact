// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public derive entry into redacted Serde expansion.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Borrowed record proving generated Serde implementations preserve generics.
#[derive(Redact)]
#[redact(serde)]
struct BorrowedRecord<'a> {
    /// Visible borrowed text.
    visible: &'a str,
    /// Secret owned text.
    #[redact(level = "secret")]
    secret: String,
}

/// Verifies the public derive emits a usable Serde implementation for generics.
#[test]
fn test_serde_entry_preserves_type_generics() {
    let value = BorrowedRecord {
        visible: "shown",
        secret: String::from("raw-secret"),
    };

    assert_eq!(
        serde_json::to_value(value.redacted())
            .expect("borrowed redacted record serializes"),
        serde_json::json!({
            "visible": "shown",
            "secret": "<redacted>",
        }),
    );
}
