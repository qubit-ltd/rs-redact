// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "http")]

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;

use http::HeaderValue;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REQUESTED_BYTES: Cell<usize> = const { Cell::new(0) };
    static MAX_REQUEST: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        Self::record(layout.size());
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        Self::record(size);
        result
    }
}

impl CountingAllocator {
    fn record(bytes: usize) {
        COUNTING.with(|counting| {
            if counting.get() {
                ALLOCATIONS.with(|value| value.set(value.get().saturating_add(1)));
                REQUESTED_BYTES.with(|value| value.set(value.get().saturating_add(bytes)));
                MAX_REQUEST.with(|value| value.set(value.get().max(bytes)));
            }
        });
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct CountingGuard;

impl CountingGuard {
    fn start() -> Self {
        ALLOCATIONS.with(|value| value.set(0));
        REQUESTED_BYTES.with(|value| value.set(0));
        MAX_REQUEST.with(|value| value.set(0));
        COUNTING.with(|value| value.set(true));
        Self
    }
}

impl Drop for CountingGuard {
    fn drop(&mut self) {
        COUNTING.with(|value| value.set(false));
    }
}

fn measure<T>(operation: impl FnOnce() -> T) -> ((usize, usize, usize), T) {
    let guard = CountingGuard::start();
    let result = operation();
    drop(guard);
    let counts = (
        ALLOCATIONS.with(Cell::get),
        REQUESTED_BYTES.with(Cell::get),
        MAX_REQUEST.with(Cell::get),
    );
    (counts, result)
}

fn disabled_redactor(max_output_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::disabled();
    policy
        .to_builder()
        .limits(|limits| {
            limits.max_input_bytes(128 * 1024).max_output_bytes(max_output_bytes);
        })
        .expect("limits are valid")
        .build()
        .map(Redactor::new)
        .expect("disabled policy with limits is valid")
}

fn assert_bounded_output(output: &qubit_redact::RedactionTextOutput) {
    assert!(output.summary().is_redaction_disabled());
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(!output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(output.text().as_str().len() <= 16);
}

#[test]
fn test_disabled_large_body_uses_bounded_temporary_allocations() {
    let redactor = disabled_redactor(16);
    let content_type = HeaderValue::from_static("text/plain");
    let ascii = vec![b'x'; 48 * 1024];
    let mixed = "\u{0001}雪\u{202e}".repeat(8 * 1024).into_bytes();
    let invalid = [vec![b'x'; 24 * 1024], vec![0xff; 24 * 1024]].concat();
    let warmup = BodyCapture::complete(b"warmup");
    let _ = redactor.redact_http_body(warmup, Some(&content_type));

    for bytes in [&ascii, &mixed, &invalid] {
        for length in [4 * 1024, 48 * 1024] {
            let capture = BodyCapture::complete(&bytes[..length]);
            let ((allocations, requested_bytes, maximum_request), output) =
                measure(|| redactor.redact_http_body(capture, Some(&content_type)));
            eprintln!(
                "body_len={length} allocations={allocations} requested_bytes={requested_bytes} maximum_request={maximum_request}"
            );
            assert!(
                maximum_request < 4 * 1024,
                "largest allocation request: {maximum_request}"
            );
            assert!(
                requested_bytes < 8 * 1024,
                "total requested allocation bytes: {requested_bytes}"
            );
            assert_bounded_output(&output);
        }
    }
}

#[test]
fn test_disabled_body_keeps_limit_marker_and_completion_semantics() {
    let bytes = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let content_type = HeaderValue::from_static("text/plain");
    for (limit, expected, completion) in [
        (0, "", RedactionCompletion::Exhausted),
        (10, "", RedactionCompletion::Exhausted),
        (11, "<truncated>", RedactionCompletion::Truncated),
        (12, "x<truncated>", RedactionCompletion::Truncated),
        (16, "xxxxx<truncated>", RedactionCompletion::Truncated),
    ] {
        let output = disabled_redactor(limit).redact_http_body(BodyCapture::complete(bytes), Some(&content_type));
        assert_eq!(output.text().as_str(), expected, "limit {limit}");
        assert_eq!(output.summary().completion(), completion, "limit {limit}");
        assert!(output.summary().is_redaction_disabled());
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert!(!output.summary().reasons().contains(RedactionReason::SourceTruncated));
        assert_eq!(output.summary().usage().output_bytes(), expected.len());
    }

    let exact = disabled_redactor(6).redact_http_body(BodyCapture::complete(b"a\nb"), Some(&content_type));
    assert_eq!(exact.text().as_str(), "a\\nb");
    assert_eq!(exact.summary().completion(), RedactionCompletion::Complete);
    assert!(!exact.summary().reasons().contains(RedactionReason::OutputLimitReached));
}

#[test]
fn test_disabled_body_lossy_utf8_and_source_truncation_are_preserved() {
    let content_type = HeaderValue::from_static("text/plain");
    let bytes = b"snow=\xe9\x9b\xaa\nrtl=\xe2\x80\xae bad=\xff tail=\xe2\x82";
    let expected = String::from_utf8_lossy(bytes)
        .replace('\n', "\\n")
        .replace('\u{202e}', "\\u{202e}");
    let output = disabled_redactor(256).redact_http_body(BodyCapture::complete(bytes), Some(&content_type));
    assert_eq!(output.text().as_str(), expected);
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().is_redaction_disabled());

    for capture in [
        BodyCapture::truncated(b"visible<truncated>", 24).expect("capture is truncated"),
        BodyCapture::truncated_unknown(b"visible<truncated>"),
    ] {
        let output = disabled_redactor(64).redact_http_body(capture, Some(&content_type));
        assert_eq!(output.text().as_str(), "visible<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::SourceTruncated));
        assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    }
}

#[test]
fn test_disabled_body_text_metadata_matches_native_metadata() {
    let redactor = disabled_redactor(16);
    let body = BodyCapture::complete(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    let native_type = HeaderValue::from_static("text/plain");
    let native = redactor.redact_http_body(body, Some(&native_type));
    let textual = redactor.redact_http_body_with_content_type_text(body, Some("text/plain"));
    assert_eq!(native.text().as_str(), textual.text().as_str());
    assert_eq!(native.summary().completion(), textual.summary().completion());
    assert_eq!(native.summary().reasons(), textual.summary().reasons());
    assert_eq!(native.summary().usage(), textual.summary().usage());
}

#[test]
fn test_disabled_complete_marker_tail_matches_composer_and_batch() {
    let output_limit = 16;
    let body_text = format!("{}<truncated>", "x".repeat(output_limit + 1));
    let capture = BodyCapture::complete(body_text.as_bytes());
    let content_type = HeaderValue::from_static("text/plain");
    let redactor = disabled_redactor(output_limit);

    // This places the literal marker exactly at the helper's retained-prefix
    // threshold: output limit + marker length + one byte of evidence.
    assert_eq!(body_text.len(), output_limit + "<truncated>".len() + 1);

    let one_shot = redactor.redact_http_body(capture, Some(&content_type));
    let composed = redactor
        .text_composer()
        .http(|http| {
            http.body(capture, Some(&content_type));
        })
        .finish();
    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_body(capture, Some(&content_type));
    let batched = batch.finish_with_marker("<incomplete>");

    for output in [&one_shot, &composed] {
        assert_eq!(output.text().as_str(), "xxxxx<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().is_redaction_disabled());
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert!(!output.summary().reasons().contains(RedactionReason::SourceTruncated));
        assert_eq!(output.summary().usage().output_bytes(), output_limit);
    }
    assert_eq!(composed.summary().reasons(), one_shot.summary().reasons());
    assert_eq!(composed.summary().usage(), one_shot.summary().usage());
    assert_eq!(batched.text(handle).as_str(), "<incomplete>");
    assert_eq!(batched.summary().completion(), one_shot.summary().completion());
    assert_eq!(batched.summary().reasons(), one_shot.summary().reasons());
    assert_eq!(batched.summary().usage(), one_shot.summary().usage());
}

#[test]
fn test_disabled_incomplete_body_batch_uses_fallback_and_keeps_reasons() {
    let redactor = disabled_redactor(64);
    let capture = BodyCapture::truncated_unknown(b"visible");
    let content_type = HeaderValue::from_static("text/plain");
    let one_shot = redactor.redact_http_body(capture, Some(&content_type));
    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_body(capture, Some(&content_type));
    let output = batch.finish_with_marker("<incomplete>");
    assert_eq!(output.text(handle).as_str(), "<incomplete>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::SourceTruncated));
    assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(output.summary().reasons(), one_shot.summary().reasons());
    assert_eq!(output.summary().usage(), one_shot.summary().usage());
    assert_eq!(output.summary().usage().output_bytes(), "visible<truncated>".len());
}
