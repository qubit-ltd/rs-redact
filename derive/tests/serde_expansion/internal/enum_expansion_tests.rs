// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for enum dispatch and skipped-variant errors.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Enum whose selected variants are explicitly excluded from serialization.
#[derive(Redact)]
#[redact(serde)]
enum SkippedVariants {
    /// Skipped named variant.
    #[serde(skip)]
    Named {
        /// Hidden payload.
        value: String,
    },
    /// Skipped tuple variant.
    #[serde(skip)]
    Tuple(String),
    /// Skipped unit variant.
    #[serde(skip)]
    Ready,
}

/// Verifies every skipped variant shape returns its exact public error.
#[test]
fn test_serde_enum_dispatch_rejects_selected_skipped_variants() {
    let cases = [
        (
            serde_json::to_value(
                SkippedVariants::Named {
                    value: String::from("raw"),
                }
                .redacted(),
            )
            .expect_err("a selected skipped named variant is rejected")
            .to_string(),
            "cannot serialize skipped redacted variant `Named`",
        ),
        (
            serde_json::to_value(
                SkippedVariants::Tuple(String::from("raw")).redacted(),
            )
            .expect_err("a selected skipped tuple variant is rejected")
            .to_string(),
            "cannot serialize skipped redacted variant `Tuple`",
        ),
        (
            serde_json::to_value(SkippedVariants::Ready.redacted())
                .expect_err("a selected skipped unit variant is rejected")
                .to_string(),
            "cannot serialize skipped redacted variant `Ready`",
        ),
    ];

    for (actual, expected) in cases {
        assert_eq!(actual, expected);
    }
}
