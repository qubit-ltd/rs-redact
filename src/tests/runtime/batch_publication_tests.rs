// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Crate-internal batch publication contracts.

use crate::RedactedText;
use crate::RedactionHandle;
use crate::RedactionHandleError;
use crate::RedactionSummary;
use crate::RedactionTextOutput;
use crate::runtime::BatchPublication;

/// Constructs neutral accounting for publication storage tests.
fn complete_summary() -> RedactionSummary {
    RedactionSummary::from_parts(
        false,
        crate::RedactionCompletion::Complete,
        crate::RedactionReasons::empty(),
        crate::RedactionUsage::empty(),
    )
}

/// An invalid same-batch index is distinct from a cross-batch handle.
#[test]
fn test_resolve_reports_missing_same_batch_item() {
    let output = BatchPublication::new(7, Vec::new(), complete_summary());

    assert_eq!(*output.summary(), complete_summary());
    assert_eq!(
        output.resolve(RedactionHandle::new(7, 0)),
        Err(RedactionHandleError::MissingItem)
    );
}

/// Valid items resolve by insertion index without exposing that index
/// publicly.
#[test]
fn test_resolve_returns_published_batch_item() {
    let item = RedactionTextOutput::new(RedactedText::from_escaped("item"), complete_summary());
    let output = BatchPublication::new(3, vec![item], complete_summary());

    assert_eq!(
        output
            .resolve(RedactionHandle::new(3, 0))
            .expect("matching private handle resolves")
            .text()
            .as_str(),
        "item"
    );
}
