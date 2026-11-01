// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "serde")]

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;
use std::io;

use qubit_redact::RedactionPolicy;
#[cfg(feature = "derive")]
use qubit_redact::Redactor;
use qubit_redact::domain::internal::BudgetSerialize;
use qubit_redact::domain::internal::RedactSerializeScope;
use serde::Serialize;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        Self::record();
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        Self::record();
        result
    }
}

impl CountingAllocator {
    fn record() {
        let _ = COUNTING.try_with(|counting| {
            if counting.get() {
                let _ = ALLOCATIONS.try_with(|allocations| allocations.set(allocations.get() + 1));
            }
        });
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct CountingGuard;

impl CountingGuard {
    fn start() -> Self {
        ALLOCATIONS.with(|allocations| allocations.set(0));
        COUNTING.with(|counting| counting.set(true));
        Self
    }
}

impl Drop for CountingGuard {
    fn drop(&mut self) {
        let _ = COUNTING.try_with(|counting| counting.set(false));
    }
}

fn measure<T>(operation: impl FnOnce() -> T) -> (usize, T) {
    let guard = CountingGuard::start();
    let result = operation();
    drop(guard);
    let allocations = ALLOCATIONS.with(Cell::get);
    (allocations, result)
}

fn serialize_to_sink<T: Serialize>(value: &T, policy: &RedactionPolicy) -> usize {
    let _scope = RedactSerializeScope::new(policy);
    let (allocations, result) =
        measure(|| BudgetSerialize::new(value).serialize(&mut serde_json::Serializer::new(io::sink())));
    result.expect("budgeted value should serialize");
    allocations
}

fn assert_bounded_growth(label: &str, samples: &[(usize, usize)]) {
    let minimum = samples.iter().map(|sample| sample.1).min().expect("nonempty samples");
    let maximum = samples.iter().map(|sample| sample.1).max().expect("nonempty samples");
    assert!(
        maximum.saturating_sub(minimum) <= 2,
        "{label} allocations grew with element count: {samples:?}",
    );
}

fn values<T: Serialize + Clone>(n: usize, value: T) -> Vec<T> {
    vec![value; n]
}

fn policy() -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_collection_items(2048)
                .max_nodes(4096)
                .max_input_bytes(65_536)
                .max_serde_payload_bytes(65_536);
        })
        .expect("limits should build")
        .build()
        .expect("policy should build")
}

#[test]
fn test_scalar_counting_allocations_do_not_scale_with_numeric_elements() {
    let policy = policy();
    let mut numeric = Vec::new();
    let mut strings = Vec::new();
    for count in [0, 1, 16, 256] {
        let numbers = values(count, 123_456_789_u64);
        let texts = values(count, String::from("123456789"));
        let _ = serialize_to_sink(&numbers, &policy);
        let _ = serialize_to_sink(&texts, &policy);
        numeric.push((count, serialize_to_sink(&numbers, &policy)));
        strings.push((count, serialize_to_sink(&texts, &policy)));
    }
    eprintln!("scalar allocation counts: numeric={numeric:?}, strings={strings:?}");
    let numeric_growth = numeric[3].1.saturating_sub(numeric[0].1);
    let string_growth = strings[3].1.saturating_sub(strings[0].1);
    assert!(
        numeric_growth <= string_growth + 2,
        "numeric allocation growth ({numeric_growth}) exceeded string control ({string_growth})"
    );
    assert_bounded_growth("numeric", &numeric);
    assert_bounded_growth("strings", &strings);
}

#[cfg(feature = "derive")]
#[derive(qubit_redact::Redact)]
struct NumberView {
    values: Vec<u64>,
}

#[cfg(feature = "derive")]
#[derive(qubit_redact::Redact)]
struct StringView {
    values: Vec<String>,
}

#[cfg(feature = "derive")]
#[test]
fn test_redact_view_scalar_counting_allocations_do_not_scale() {
    let policy = policy();
    let redactor = Redactor::new(policy.clone());
    let mut numeric = Vec::new();
    let mut strings = Vec::new();
    for count in [0, 1, 16, 256] {
        let numbers = NumberView {
            values: values(count, 123_456_789_u64),
        };
        let texts = StringView {
            values: values(count, String::from("123456789")),
        };
        let numeric_view = redactor.redact_view(&numbers);
        let string_view = redactor.redact_view(&texts);
        let _ = serialize_to_sink(&numeric_view, &policy);
        let _ = serialize_to_sink(&string_view, &policy);
        numeric.push((count, serialize_to_sink(&numeric_view, &policy)));
        strings.push((count, serialize_to_sink(&string_view, &policy)));
    }
    eprintln!("redact_view allocation counts: numeric={numeric:?}, strings={strings:?}");
    let numeric_growth = numeric[3].1.saturating_sub(numeric[0].1);
    let string_growth = strings[3].1.saturating_sub(strings[0].1);
    assert!(
        numeric_growth <= string_growth + 2,
        "redact_view numeric allocation growth ({numeric_growth}) exceeded string control ({string_growth})"
    );
    assert_bounded_growth("redact_view numeric", &numeric);
    assert_bounded_growth("redact_view strings", &strings);
}
