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
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REQUESTED_BYTES: Cell<usize> = const { Cell::new(0) };
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
            }
        });
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct CountingGuard;

type AllocationCase<'a> = (&'static str, Box<dyn Fn() + 'a>);

impl CountingGuard {
    fn start() -> Self {
        ALLOCATIONS.with(|value| value.set(0));
        REQUESTED_BYTES.with(|value| value.set(0));
        COUNTING.with(|value| value.set(true));
        Self
    }
}

impl Drop for CountingGuard {
    fn drop(&mut self) {
        COUNTING.with(|value| value.set(false));
    }
}

fn measure<T>(operation: impl FnOnce() -> T) -> ((usize, usize), T) {
    let guard = CountingGuard::start();
    let result = operation();
    drop(guard);
    let counts = (ALLOCATIONS.with(Cell::get), REQUESTED_BYTES.with(Cell::get));
    (counts, result)
}

fn parameterized_content_type(count: usize) -> String {
    let mut value = String::from("application/x-www-form-urlencoded");
    for index in 0..count {
        value.push_str(&format!(";p{index}=abcdefgh"));
    }
    value
}

fn body() -> &'static [u8] {
    b"password=raw-secret&public=ok"
}

fn verify_text(text: &str) {
    assert!(text.contains("public=ok"), "public field should be preserved: {text}");
    assert!(!text.contains("raw-secret"), "password value should be hidden: {text}");
}

#[test]
fn test_public_http_content_type_allocation_bounds() {
    let redactor = Redactor::standard();
    let body = BodyCapture::complete(body());
    let mut inputs: Vec<(String, usize)> = [0, 100, 2_000]
        .into_iter()
        .map(|count| (parameterized_content_type(count), count))
        .collect();
    inputs.push((
        format!(
            "application/x-www-form-urlencoded;unknown=\"{}\"",
            "q".repeat(16 * 1024)
        ),
        0,
    ));
    let mut measurements = Vec::new();
    for (content_type, count) in inputs {
        let native = HeaderValue::from_str(&content_type).expect("metadata is a valid header value");
        let cases: Vec<AllocationCase<'_>> = vec![
            (
                "native-one-shot",
                Box::new(|| {
                    let output = redactor.redact_http_body(body, Some(&native));
                    verify_text(output.text().as_str());
                }),
            ),
            (
                "text-one-shot",
                Box::new(|| {
                    let output = redactor.redact_http_body_with_content_type_text(body, Some(&content_type));
                    verify_text(output.text().as_str());
                }),
            ),
            (
                "composer",
                Box::new(|| {
                    let output = redactor
                        .text_composer()
                        .http(|http| {
                            http.body_with_content_type_text(body, Some(&content_type));
                        })
                        .finish();
                    verify_text(output.text().as_str());
                }),
            ),
            (
                "batch",
                Box::new(|| {
                    let mut batch = redactor.diagnostic_batch();
                    let handle = batch.redact_http_body_with_content_type_text(body, Some(&content_type));
                    let report = batch.finish();
                    verify_text(report.text(handle).as_str());
                }),
            ),
            (
                "inspection",
                Box::new(|| {
                    let result = redactor.inspect_http_body_with_content_type_text(body, Some(&content_type));
                    assert!(result.is_ok(), "valid form body should be inspectable");
                }),
            ),
        ];
        for (name, operation) in cases {
            // Warm the public path before measuring it; all inputs and metadata were built
            // above.
            operation();
            let ((allocations, requested_bytes), ()) = measure(operation);
            measurements.push((count, content_type.len(), name, allocations, requested_bytes));
            eprintln!(
                "profile=test opt_level=0 debug=0 input_params={count} input_bytes={} case={name} alloc_realloc_calls={allocations} requested_bytes={requested_bytes}",
                content_type.len(),
            );
        }
    }
    for (count, input_size, name, allocations, requested_bytes) in &measurements {
        if *count == 2_000 && *name != "inspection" {
            // On Rust 1.94.0 x86_64 Linux, the pre-optimization native/text/composer
            // baseline was 8,674 calls and 492,547 requested bytes. These ceilings
            // stay below 70% of that baseline with room for platform variation.
            assert!(
                *allocations < 6_000 && *requested_bytes < 340_000,
                "2,000 unknown parameters must stay below the pre-optimization envelope: {name}, {allocations} alloc/realloc calls, {requested_bytes} requested bytes",
            );
        }
        if *count == 2_000 && *name == "inspection" {
            // Inspection has its own pre-optimization baseline: 4,336 calls and
            // 246,158 requested bytes under the same measurement conditions.
            assert!(
                *allocations < 3_000 && *requested_bytes < 170_000,
                "2,000 unknown parameters must stay below the pre-optimization inspection envelope: {allocations} alloc/realloc calls, {requested_bytes} requested bytes",
            );
        }
        if *input_size == 16_428 && *name != "inspection" {
            // The 16 KiB unknown quoted value previously requested 66,685 bytes
            // for native/text/composer rendering due to needless decoding.
            assert!(
                *requested_bytes < 8_000,
                "unknown quoted value should not create a decoded copy: {name}, {requested_bytes} requested bytes",
            );
        }
    }
}
