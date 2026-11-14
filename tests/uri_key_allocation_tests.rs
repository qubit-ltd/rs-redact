// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "uri")]

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::uri::UriRedactionBoundary;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static REQUESTED_BYTES: Cell<usize> = const { Cell::new(0) };
    static MAX_REQUEST: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc(layout) };
        Self::record(layout.size());
        result
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
    fn record(size: usize) {
        let _ = COUNTING.try_with(|enabled| {
            if enabled.get() {
                let _ = CALLS.try_with(|calls| calls.set(calls.get() + 1));
                let _ = REQUESTED_BYTES.try_with(|total| total.set(total.get().saturating_add(size)));
                let _ = MAX_REQUEST.try_with(|maximum| maximum.set(maximum.get().max(size)));
            }
        });
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measured<T>(f: impl FnOnce() -> T) -> ((usize, usize, usize), T) {
    CALLS.with(|value| value.set(0));
    REQUESTED_BYTES.with(|value| value.set(0));
    MAX_REQUEST.with(|value| value.set(0));
    COUNTING.with(|value| value.set(true));
    let output = f();
    COUNTING.with(|value| value.set(false));
    (
        (
            CALLS.with(Cell::get),
            REQUESTED_BYTES.with(Cell::get),
            MAX_REQUEST.with(Cell::get),
        ),
        output,
    )
}

fn make_redactor() -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_key_bytes(256).max_input_bytes(64 * 1024);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    Redactor::new(policy)
}

#[test]
fn test_rejected_uri_keys_do_not_allocate_a_decoded_buffer_proportional_to_raw_length() {
    let redactor = make_redactor();
    let short = format!("custom://example.test/?{}=value", "%61".repeat(300));
    let long = format!("custom://example.test/?{}=value", "%61".repeat(20_000));
    assert!(long.len() < 64 * 1024);
    let boundary = UriRedactionBoundary::new(redactor.policy());

    let exercise = |input: &str| {
        let _ = redactor.redact_uri(input);
        let _ = redactor.inspect_uri(input);
        let _ = redactor
            .text_composer()
            .uri(|uri| {
                uri.value(input);
            })
            .finish();
        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_uri(input);
        let _ = batch.finish().text(handle);
        let _ = boundary.redact_uri(input);
        let _ = boundary.inspect_uri(input);
    };
    exercise(&short);
    exercise(&long);
    for input in [&short, &long] {
        let ((calls, bytes, max), _) = measured(|| exercise(input));
        eprintln!(
            "rr02/rejected-input-{} calls={calls} requested_bytes={bytes} max_request={max}",
            input.len()
        );
        assert!(
            max < 8 * 1024,
            "input {} requested allocation of {max} bytes",
            input.len()
        );
    }

    let ordinary = format!(
        "custom://example.test/?{}",
        (0..128)
            .map(|i| format!("field{i}=value{i}"))
            .collect::<Vec<_>>()
            .join("&")
    );
    let encoded = format!(
        "custom://example.test/?{}",
        (0..128)
            .map(|i| format!("field%{:02X}=value{i}", (b'a' + (i % 26) as u8)))
            .collect::<Vec<_>>()
            .join("&")
    );
    for (label, input) in [
        ("short", "custom://example.test/?public=value&token=raw-secret"),
        ("ordinary-128", ordinary.as_str()),
        ("encoded-128", encoded.as_str()),
    ] {
        for (entry, operation) in [
            ("one-shot", 0usize),
            ("inspection", 1),
            ("single-item-batch", 2),
            ("composer", 3),
        ] {
            let ((calls, bytes, max), _) = measured(|| match operation {
                0 => {
                    let _ = redactor.redact_uri(input);
                }
                1 => {
                    let _ = redactor.inspect_uri(input);
                }
                2 => {
                    let mut batch = redactor.diagnostic_batch();
                    let handle = batch.redact_uri(input);
                    let _ = batch.finish().text(handle);
                }
                _ => {
                    let _ = redactor
                        .text_composer()
                        .uri(|writer| {
                            writer.value(input);
                        })
                        .finish();
                }
            });
            eprintln!("rr02/{label}/{entry} calls={calls} requested_bytes={bytes} max_request={max}");
        }
    }
}
