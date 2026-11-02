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
    static LARGE_REQUESTS: Cell<usize> = const { Cell::new(0) };
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
        let _ = COUNTING.try_with(|counting| {
            if counting.get() {
                let _ = ALLOCATIONS.try_with(|allocations| allocations.set(allocations.get() + 1));
                let _ = REQUESTED_BYTES.try_with(|requested| {
                    requested.set(requested.get().saturating_add(bytes));
                });
                let _ = MAX_REQUEST.try_with(|maximum| maximum.set(maximum.get().max(bytes)));
                if bytes >= 1024 {
                    let _ = LARGE_REQUESTS.try_with(|large| large.set(large.get() + 1));
                }
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
        LARGE_REQUESTS.with(|value| value.set(0));
        COUNTING.with(|value| value.set(true));
        Self
    }
}

impl Drop for CountingGuard {
    fn drop(&mut self) {
        let _ = COUNTING.try_with(|value| value.set(false));
    }
}

fn measure<T>(operation: impl FnOnce() -> T) -> ((usize, usize, usize, usize), T) {
    let guard = CountingGuard::start();
    let result = operation();
    drop(guard);
    let counts = (
        ALLOCATIONS.with(Cell::get),
        REQUESTED_BYTES.with(Cell::get),
        MAX_REQUEST.with(Cell::get),
        LARGE_REQUESTS.with(Cell::get),
    );
    (counts, result)
}

fn disabled_url_redactor(max_output_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::disabled();
    let policy = policy
        .to_builder()
        .limits(|limits| {
            limits.max_input_bytes(64 * 1024).max_output_bytes(max_output_bytes);
        })
        .expect("limits are valid")
        .build()
        .expect("disabled policy with limits is valid");
    Redactor::new(policy)
}

#[test]
fn test_disabled_url_preserves_bounded_text_across_entry_points() {
    let source = "https://example.test/?q=雪\n\u{0001}<truncated>";
    for (limit, expected, completion) in [
        (0, "", RedactionCompletion::Exhausted),
        (10, "", RedactionCompletion::Exhausted),
        (11, "<truncated>", RedactionCompletion::Truncated),
        (12, "h<truncated>", RedactionCompletion::Truncated),
        (16, "https<truncated>", RedactionCompletion::Truncated),
        (
            128,
            "https://example.test/?q=雪\\n\\u{1}<truncated>",
            RedactionCompletion::Complete,
        ),
    ] {
        let redactor = disabled_url_redactor(limit);
        let direct = redactor.redact_http_url(source);
        let composed = redactor
            .text_composer()
            .http(|http| {
                http.url(source);
            })
            .finish();
        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_http_url(source);
        let report = batch.finish_with_marker("<fallback>");
        for (text, summary) in [
            (direct.text().as_str(), direct.summary()),
            (composed.text().as_str(), composed.summary()),
        ] {
            assert_eq!(text, expected, "output limit {limit}");
            assert_eq!(summary.completion(), completion, "output limit {limit}");
            assert!(summary.is_redaction_disabled());
            assert_eq!(
                summary.reasons().contains(RedactionReason::OutputLimitReached),
                limit < source.len()
            );
            assert!(!summary.reasons().contains(RedactionReason::InputLimitReached));
            assert_eq!(summary.usage().output_bytes(), expected.len());
        }
        let batch_text = report.text(handle).as_str();
        assert_eq!(
            batch_text,
            if completion == RedactionCompletion::Complete {
                expected
            } else {
                "<fallback>"
            }
        );
        assert!(report.summary().is_redaction_disabled());
        assert_eq!(report.summary().completion(), completion);
        assert_eq!(
            report.summary().reasons().contains(RedactionReason::OutputLimitReached),
            limit < source.len()
        );
        assert!(!report.summary().reasons().contains(RedactionReason::InputLimitReached));
        assert_eq!(
            report.summary().usage().output_bytes(),
            if limit < "<truncated>".len() {
                0
            } else if completion == RedactionCompletion::Complete {
                batch_text.len()
            } else {
                limit
            },
        );
    }
}

#[test]
fn test_disabled_long_url_allocation_measurements() {
    let redactor = disabled_url_redactor(16);
    let make_url = |length: usize| format!("https://example.test/?q={}", "x".repeat(length));
    let short = make_url(4 * 1024);
    let long = make_url(48 * 1024);
    let warmup = redactor.redact_http_url("https://example.test/?q=warmup");
    assert_eq!(warmup.text().as_str(), "https<truncated>");

    for input in [&short, &long] {
        for _ in 0..3 {
            let ((calls, bytes, maximum, large), output) = measure(|| redactor.redact_http_url(input));
            assert!(output.summary().is_redaction_disabled());
            eprintln!(
                "case=disabled-url/input-{} alloc_realloc_calls={calls} requested_bytes={bytes} maximum_request={maximum} large_requests_ge_1024={large}",
                input.len(),
            );
        }
    }
}

#[test]
fn test_plain_query_and_form_allocation_baseline() {
    let redactor = Redactor::standard();
    let make_input = |count: usize| {
        let query = (0..count)
            .map(|index| format!("field{index}=value{index}"))
            .collect::<Vec<_>>()
            .join("&");
        format!("https://example.test/path?{query}")
    };
    let short = make_input(1);
    let large = make_input(128);
    let form = BodyCapture::complete(b"field=value&other=plain");
    let mut measurements = Vec::new();

    for (label, input) in [("one", short.as_str()), ("128", large.as_str())] {
        let one_shot = || {
            let output = redactor.redact_http_url(input);
            assert!(output.text().as_str().contains("field0=value0"));
        };
        one_shot();
        for _ in 0..3 {
            let ((calls, bytes, _, _), ()) = measure(one_shot);
            measurements.push((label, "one-shot", calls, bytes));
        }

        let batch = || {
            let mut batch = redactor.diagnostic_batch();
            let handle = batch.redact_http_url(input);
            let report = batch.finish();
            assert!(report.text(handle).as_str().contains("field0=value0"));
        };
        batch();
        for _ in 0..3 {
            let ((calls, bytes, _, _), ()) = measure(batch);
            measurements.push((label, "batch", calls, bytes));
        }

        let inspection = || {
            let result = redactor.inspect_http_url(input);
            assert!(result.is_ok());
        };
        inspection();
        for _ in 0..3 {
            let ((calls, bytes, _, _), ()) = measure(inspection);
            measurements.push((label, "inspection", calls, bytes));
        }
    }

    let form_redaction = || {
        let output = redactor.redact_http_body_with_content_type_text(form, Some("application/x-www-form-urlencoded"));
        assert!(output.text().as_str().contains("field=value"));
    };
    form_redaction();
    for _ in 0..3 {
        let ((calls, bytes, _, _), ()) = measure(form_redaction);
        measurements.push(("form", "one-shot", calls, bytes));
    }

    for (size, case, calls, bytes) in measurements {
        if size == "128" && case == "one-shot" {
            // Rust 1.94.0 x86_64 Linux, test profile: pre-optimization calls
            // were 1,047 across three identical runs. The fixed ceiling requires
            // at least 256 calls to disappear (two decodes for each of 128 values).
            assert!(
                calls <= 791,
                "128-field plain URL exceeded the pre-optimization ceiling: {calls} calls, {bytes} requested bytes",
            );
        }
        eprintln!(
            "profile=test opt_level=0 debug=0 case={size}/{case} alloc_realloc_calls={calls} requested_bytes={bytes}"
        );
    }
}
