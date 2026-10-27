// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "json")]

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::domain::internal::RedactedJsonSerializeRef;
use serde_json::to_value;

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

fn fixture(payload_bytes: usize) -> (RedactionPolicy, String) {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(1_000_000).max_nodes(1).max_output_bytes(64);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let source = format!("[\"{}\"]", "x".repeat(payload_bytes));
    (policy, source)
}

#[test]
fn test_json_text_preflight_bounds_large_rejected_tree_allocation() {
    let (policy, small) = fixture(4 * 1024);
    let (_, large) = fixture(256 * 1024);
    let redactor = Redactor::new(policy);
    let (small_max, small_output) = measure(|| redactor.redact_json(&small));
    let (large_max, large_output) = measure(|| redactor.redact_json(&large));

    assert!(small_max < 32 * 1024, "small request was {small_max}");
    assert!(large_max < 32 * 1024, "large request was {large_max}");
    assert!(
        large_max <= small_max,
        "large request {large_max} exceeded small request {small_max}"
    );
    assert!(!small_output.text().as_str().contains(&small[2..small.len() - 2]));
    assert!(!large_output.text().as_str().contains(&large[2..large.len() - 2]));
}

#[test]
fn test_serde_json_text_preflight_bounds_large_rejected_tree_allocation() {
    let (policy, small) = fixture(4 * 1024);
    let (_, large) = fixture(256 * 1024);
    let (small_max, small_output) = measure(|| to_value(RedactedJsonSerializeRef::new(small.as_str(), &policy)));
    let (large_max, large_output) = measure(|| to_value(RedactedJsonSerializeRef::new(large.as_str(), &policy)));

    assert!(small_max < 32 * 1024, "small request was {small_max}");
    assert!(large_max < 32 * 1024, "large request was {large_max}");
    assert!(
        large_max <= small_max,
        "large request {large_max} exceeded small request {small_max}"
    );
    assert_eq!(small_output.expect("small adapter output"), "<redacted>");
    assert_eq!(large_output.expect("large adapter output"), "<redacted>");
}
