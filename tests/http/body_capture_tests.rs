// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodyCapture`](qubit_redact::http::BodyCapture).

use qubit_redact::http::{
    BodyCapture,
    BodyCaptureError,
};

/// Verifies capture errors describe both conflicting byte counts.
#[test]
fn test_body_capture_error_display_describes_invalid_total() {
    assert_eq!(
        BodyCaptureError::InvalidTotalLength {
            captured: 6,
            total: 6,
        }
        .to_string(),
        "truncated body total length 6 must exceed 6 captured bytes",
    );
}

/// Verifies that a complete capture has exact, self-consistent metadata.
#[test]
fn test_body_capture_complete_sets_exact_metadata() {
    let bytes = b"abcdef";
    let capture = BodyCapture::complete(bytes);

    assert_eq!(capture.bytes(), bytes);
    assert_eq!(capture.captured_len(), bytes.len());
    assert_eq!(capture.total_len(), Some(bytes.len()));
    assert_eq!(capture.omitted_len(), Some(0));
    assert!(!capture.is_source_truncated());
}

/// Verifies that known truncated totals must strictly exceed captured bytes.
#[test]
fn test_body_capture_truncated_rejects_impossible_total() {
    let bytes = b"abcdef";

    for total in [0, bytes.len() - 1, bytes.len()] {
        assert_eq!(
            BodyCapture::truncated(bytes, Some(total)),
            Err(BodyCaptureError::InvalidTotalLength {
                captured: bytes.len(),
                total,
            }),
        );
    }
}

/// Verifies known and unknown truncated captures retain truthful metadata.
#[test]
fn test_body_capture_truncated_preserves_metadata() {
    let bytes = b"abcdef";
    let known = BodyCapture::truncated(bytes, Some(10))
        .expect("a larger total length should be valid");
    let unknown = BodyCapture::truncated(bytes, None)
        .expect("an unknown truncated total should be valid");

    assert_eq!(known.bytes(), bytes);
    assert_eq!(known.captured_len(), bytes.len());
    assert_eq!(known.total_len(), Some(10));
    assert_eq!(known.omitted_len(), Some(4));
    assert!(known.is_source_truncated());

    assert_eq!(unknown.total_len(), None);
    assert_eq!(unknown.omitted_len(), None);
    assert!(unknown.is_source_truncated());
}
