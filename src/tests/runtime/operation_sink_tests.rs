// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Crate-internal operation sink contracts.

use crate::RedactionCompletion;
use crate::RedactionReason;
use crate::runtime::OperationSink;

/// Verifies source truncation reserves the marker and provenance helpers
/// remain bounded by the operation allowance.
#[test]
fn test_source_truncation_preserves_marker_and_reason() {
    let mut sink = OperationSink::new(16, "<truncated>", false);
    assert!(sink.write_atom("visible"));
    sink.mark_truncated();
    assert_eq!(sink.remaining_bytes(), 5);

    let operation = sink.finish_with_reason(RedactionReason::SourceTruncated);
    let (text, completion, reasons) = operation.into_parts();

    assert_eq!(text, "<truncated>");
    assert_eq!(completion, RedactionCompletion::Truncated);
    assert!(reasons.contains(RedactionReason::SourceTruncated));

    let (_, completion, reasons) = OperationSink::complete("safe")
        .with_reason(RedactionReason::InvalidJson)
        .finish()
        .into_parts();
    assert_eq!(completion, RedactionCompletion::Complete);
    assert!(reasons.contains(RedactionReason::InvalidJson));
}
