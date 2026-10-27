// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(any(feature = "json", feature = "http"))]

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;

use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use serde_json::Value;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
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
                MAX_REQUEST.with(|maximum| maximum.set(maximum.get().max(bytes)));
            }
        });
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure<T>(operation: impl FnOnce() -> T) -> (usize, T) {
    MAX_REQUEST.with(|maximum| maximum.set(0));
    COUNTING.with(|counting| counting.set(true));
    let result = operation();
    COUNTING.with(|counting| counting.set(false));
    (MAX_REQUEST.with(Cell::get), result)
}

fn fixture_with_mask_size(mask_size: usize) -> (Redactor, Value, String) {
    let mask = "M".repeat(mask_size);
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .sensitive(Sensitivity::Secret, "password")
                .mask(Sensitivity::Secret, MaskPolicy::fixed(&mask));
        })
        .expect("field policy should build")
        .limits(|limits| {
            limits
                .max_output_bytes(64)
                .max_input_bytes(1_000_000)
                .max_nodes(1_024)
                .max_collection_items(4_096)
                .max_json_nodes(1_024);
        })
        .expect("limits should build")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);
    let value: Value = serde_json::from_str(&format!(
        "{{{}}}",
        (0..128)
            .map(|index| format!("\"field{index}\":{{\"password\":\"sentinel-{index}\"}}"))
            .collect::<Vec<_>>()
            .join(",")
    ))
    .expect("JSON fixture should parse");
    let text = serde_json::to_string(&value).expect("JSON fixture should serialize");
    (redactor, value, text)
}

fn fixture() -> (Redactor, Value, String) {
    fixture_with_mask_size(128 * 1024)
}

fn disabled_json_redactor_with_output_limit(max_output_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_input_bytes(1_000_000).max_output_bytes(max_output_bytes);
        })
        .expect("limit draft should build")
        .build()
        .expect("disabled policy should build");
    Redactor::new(policy)
}

fn assert_bounded_redaction(max_request: usize, output: &qubit_redact::RedactionTextOutput) {
    assert!(
        max_request < 65_536,
        "largest allocator request was {max_request} bytes"
    );
    assert!(output.text().as_str().len() <= 64);
    assert!(
        output.summary().reasons().contains(RedactionReason::OutputLimitReached),
        "text={:?} reasons={:?} completion={:?}",
        output.text().as_str(),
        output.summary().reasons(),
        output.summary().completion()
    );
    assert!(!output.text().as_str().contains("sentinel-"));
}

#[cfg(feature = "json")]
#[test]
fn test_json_value_masking_does_not_allocate_the_full_mask() {
    let (redactor, value, _) = fixture();
    let _ = redactor.redact_json_value(&value);
    let (max_request, output) = measure(|| redactor.redact_json_value(&value));
    assert_bounded_redaction(max_request, &output);
}

#[cfg(feature = "json")]
#[test]
fn test_json_text_masking_does_not_allocate_the_full_mask() {
    let (redactor, _, text) = fixture();
    let _ = redactor.redact_json(&text);
    let (max_request, output) = measure(|| redactor.redact_json(&text));
    assert_bounded_redaction(max_request, &output);
}

#[cfg(feature = "json")]
#[test]
fn test_disabled_json_passthrough_allocation_is_bounded_by_output_limit() {
    let redactor = disabled_json_redactor_with_output_limit(16);
    let _ = redactor.redact_json("\"warmup\"");
    let ordinary_small = format!("\"{}\"", "x".repeat(4 * 1024 - 2));
    let ordinary_large = format!("\"{}\"", "x".repeat(48 * 1024 - 2));
    let controls_small = "\n\u{202e}".repeat(4 * 1024 / 4);
    let controls_large = "\n\u{202e}".repeat(48 * 1024 / 4);

    let (ordinary_small_max, ordinary_small_output) = measure(|| redactor.redact_json(&ordinary_small));
    let (ordinary_large_max, ordinary_large_output) = measure(|| redactor.redact_json(&ordinary_large));
    let (controls_small_max, controls_small_output) = measure(|| redactor.redact_json(&controls_small));
    let (controls_large_max, controls_large_output) = measure(|| redactor.redact_json(&controls_large));
    eprintln!(
        "T4 max alloc bytes: ordinary={ordinary_small_max}/{ordinary_large_max}, controls={controls_small_max}/{controls_large_max}"
    );

    for (label, maximum) in [
        ("4 KiB JSON", ordinary_small_max),
        ("48 KiB JSON", ordinary_large_max),
        ("4 KiB controls", controls_small_max),
        ("48 KiB controls", controls_large_max),
    ] {
        assert!(maximum < 4 * 1024, "{label} requested {maximum} bytes");
    }
    assert!(ordinary_large_max <= ordinary_small_max);
    assert!(controls_large_max <= controls_small_max);
    for (text, output) in [
        (&ordinary_small, ordinary_small_output),
        (&ordinary_large, ordinary_large_output),
        (&controls_small, controls_small_output),
        (&controls_large, controls_large_output),
    ] {
        assert_eq!(output.text().as_str(), "<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert!(!output.summary().reasons().contains(RedactionReason::InputLimitReached));
        assert_eq!(output.summary().usage().inspected_input_bytes(), text.len());
    }
}

#[cfg(feature = "json")]
#[test]
fn test_disabled_json_passthrough_keeps_output_boundary_semantics() {
    let long_input = "this input is long";
    for (limit, expected, completion) in [
        (0, "", RedactionCompletion::Exhausted),
        (10, "", RedactionCompletion::Exhausted),
        (11, "<truncated>", RedactionCompletion::Truncated),
        (12, "<truncated>", RedactionCompletion::Truncated),
    ] {
        let output = disabled_json_redactor_with_output_limit(limit).redact_json(long_input);
        assert_eq!(output.text().as_str(), expected, "limit={limit}");
        assert_eq!(output.summary().completion(), completion, "limit={limit}");
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert_eq!(
            output.summary().usage().inspected_input_bytes(),
            if limit == 0 { 0 } else { long_input.len() }
        );
    }

    let redactor = disabled_json_redactor_with_output_limit(64);
    let text = "{\"value\":\"雪\n\u{202e}\"}";
    let expected = "{\"value\":\"雪\\n\\u{202e}\"}";
    let output = redactor.redact_json(text);
    assert_eq!(output.text().as_str(), expected);
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_json(text);
    let batch = batch.finish_with_marker("");
    assert_eq!(batch.text(handle).as_str(), expected);

    let composed = redactor
        .text_composer()
        .json(|writer| {
            writer.text(text);
        })
        .finish();
    assert_eq!(composed.text().as_str(), expected);
    assert_eq!(composed.summary().completion(), RedactionCompletion::Complete);
}

#[cfg(feature = "json")]
#[test]
fn test_invalid_json_masking_does_not_allocate_the_full_mask() {
    for mask_size in [128 * 1024, 1024 * 1024] {
        let (redactor, _, _) = fixture_with_mask_size(mask_size);
        let _ = redactor.redact_json("{");
        let (max_request, output) = measure(|| redactor.redact_json("{"));
        assert_bounded_redaction(max_request, &output);
        assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
        assert_eq!(output.text().as_str(), "<truncated>");
    }
}

#[cfg(feature = "http")]
#[test]
fn test_http_json_masking_does_not_allocate_the_full_mask() {
    use qubit_redact::formats::http::BodyCapture;

    let (redactor, _, text) = fixture();
    let _ = redactor
        .redact_http_body_with_content_type_text(BodyCapture::complete(text.as_bytes()), Some("application/json"));
    let (max_request, output) = measure(|| {
        redactor
            .redact_http_body_with_content_type_text(BodyCapture::complete(text.as_bytes()), Some("application/json"))
    });
    assert_bounded_redaction(max_request, &output);
}

#[cfg(feature = "http")]
#[test]
fn test_http_ndjson_masking_does_not_allocate_the_full_mask() {
    use qubit_redact::formats::http::BodyCapture;

    let (redactor, _, text) = fixture();
    let ndjson = format!("{text}\n{text}\n");
    let _ = redactor.redact_http_body_with_content_type_text(
        BodyCapture::complete(ndjson.as_bytes()),
        Some("application/x-ndjson"),
    );
    let (max_request, output) = measure(|| {
        redactor.redact_http_body_with_content_type_text(
            BodyCapture::complete(ndjson.as_bytes()),
            Some("application/x-ndjson"),
        )
    });
    assert_bounded_redaction(max_request, &output);
}

#[cfg(feature = "http")]
#[test]
fn test_http_multipart_json_masking_does_not_allocate_the_full_mask() {
    use qubit_redact::formats::http::BodyCapture;

    let (redactor, _, text) = fixture();
    let body = format!(
        "--b\r\nContent-Disposition: form-data; name=\"payload\"\r\nContent-Type: application/json\r\n\r\n{text}\r\n--b--\r\n"
    );
    let _ = redactor.redact_http_body_with_content_type_text(
        BodyCapture::complete(body.as_bytes()),
        Some("multipart/form-data; boundary=b"),
    );
    let (max_request, output) = measure(|| {
        redactor.redact_http_body_with_content_type_text(
            BodyCapture::complete(body.as_bytes()),
            Some("multipart/form-data; boundary=b"),
        )
    });
    assert_bounded_redaction(max_request, &output);
}
