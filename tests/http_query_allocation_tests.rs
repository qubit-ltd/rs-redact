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
        let _ = COUNTING.try_with(|counting| {
            if counting.get() {
                let _ = ALLOCATIONS.try_with(|allocations| allocations.set(allocations.get() + 1));
                let _ = REQUESTED_BYTES.try_with(|requested| {
                    requested.set(requested.get().saturating_add(bytes));
                });
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
        COUNTING.with(|value| value.set(true));
        Self
    }
}

impl Drop for CountingGuard {
    fn drop(&mut self) {
        let _ = COUNTING.try_with(|value| value.set(false));
    }
}

fn measure<T>(operation: impl FnOnce() -> T) -> ((usize, usize), T) {
    let guard = CountingGuard::start();
    let result = operation();
    drop(guard);
    let counts = (ALLOCATIONS.with(Cell::get), REQUESTED_BYTES.with(Cell::get));
    (counts, result)
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
            let ((calls, bytes), ()) = measure(one_shot);
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
            let ((calls, bytes), ()) = measure(batch);
            measurements.push((label, "batch", calls, bytes));
        }

        let inspection = || {
            let result = redactor.inspect_http_url(input);
            assert!(result.is_ok());
        };
        inspection();
        for _ in 0..3 {
            let ((calls, bytes), ()) = measure(inspection);
            measurements.push((label, "inspection", calls, bytes));
        }
    }

    let form_redaction = || {
        let output = redactor.redact_http_body_with_content_type_text(form, Some("application/x-www-form-urlencoded"));
        assert!(output.text().as_str().contains("field=value"));
    };
    form_redaction();
    for _ in 0..3 {
        let ((calls, bytes), ()) = measure(form_redaction);
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
