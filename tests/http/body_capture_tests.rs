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
    let bytes = std::hint::black_box(b"abcdef".as_slice());
    let capture = BodyCapture::complete(bytes);

    assert_eq!(capture.bytes(), bytes);
    assert_eq!(capture.captured_len(), bytes.len());
    assert_eq!(capture.total_len(), Some(bytes.len()));
    assert_eq!(capture.omitted_len(), Some(0));
    assert!(!capture.is_source_truncated());
}

/// Verifies debug output exposes metadata without captured body bytes.
#[test]
fn test_body_capture_debug_does_not_expose_bytes() {
    let capture = BodyCapture::truncated(b"debug-body-secret", Some(32))
        .expect("the total length exceeds the captured length");
    let rendered = format!("{capture:?}");

    assert!(!rendered.contains("debug-body-secret"));
    assert!(rendered.contains("captured_len"));
    assert!(rendered.contains("omitted_len"));
    assert!(rendered.contains("source_truncated: true"));
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

/// Verifies a presentation prefix preserves complete or truncated source
/// metadata without a fallible impossible branch.
#[test]
fn test_body_capture_prefix_preserves_truthful_metadata() {
    let bytes = b"abcdef";
    let complete = BodyCapture::prefix(bytes, bytes.len());
    let truncated = BodyCapture::prefix(bytes, 3);
    let empty_prefix = BodyCapture::prefix(bytes, 0);

    assert_eq!(complete, BodyCapture::complete(bytes));
    assert_eq!(truncated.bytes(), b"abc");
    assert_eq!(truncated.total_len(), Some(bytes.len()));
    assert_eq!(truncated.omitted_len(), Some(3));
    assert!(truncated.is_source_truncated());
    assert_eq!(empty_prefix.bytes(), b"");
    assert_eq!(empty_prefix.total_len(), Some(bytes.len()));
    assert_eq!(empty_prefix.omitted_len(), Some(bytes.len()));
    assert!(empty_prefix.is_source_truncated());
}

/// Verifies an unknown-length truncated capture is infallible and never
/// misrepresented as complete input.
#[test]
fn test_body_capture_truncated_unknown_preserves_truncation() {
    let bytes = std::hint::black_box(b"captured".as_slice());
    let capture = BodyCapture::truncated_unknown(bytes);

    assert_eq!(capture.bytes(), b"captured");
    assert_eq!(capture.total_len(), None);
    assert_eq!(capture.omitted_len(), None);
    assert!(capture.is_source_truncated());
}
