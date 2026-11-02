// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression checks for built-in redactor construction allocations.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;
use std::hint::black_box;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

impl CountingAllocator {
    fn record() {
        let _ = ACTIVE.try_with(|active| {
            if active.get() {
                ALLOCATIONS.with(|count| count.set(count.get() + 1));
            }
        });
    }
}

// SAFETY: Each operation delegates to the corresponding System allocator
// operation.
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
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        Self::record();
        pointer
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct CountingGuard;

impl Drop for CountingGuard {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
    }
}

fn allocations(operation: impl FnOnce()) -> usize {
    ALLOCATIONS.with(|count| count.set(0));
    ACTIVE.with(|active| active.set(true));
    let guard = CountingGuard;
    operation();
    drop(guard);
    ALLOCATIONS.with(Cell::get)
}

/// Warm built-in constructors must not allocate per returned instance.
#[test]
fn test_warm_builtin_constructors_do_not_allocate() {
    let standard = Redactor::standard();
    let _strict = Redactor::strict();
    let _default = Redactor::default();
    assert_eq!(allocations(|| {}), 0);
    for constructor in [
        Redactor::standard as fn() -> Redactor,
        Redactor::strict,
        Redactor::default,
    ] {
        let count = allocations(|| {
            for _ in 0..1_000 {
                drop(black_box(constructor()));
            }
        });
        assert_eq!(count, 0, "warm built-in construction must not allocate");
    }
    assert_eq!(allocations(|| drop(black_box(standard.clone()))), 0);
}

struct RestoreDefault(Redactor);

impl Drop for RestoreDefault {
    fn drop(&mut self) {
        let _ = Redactor::replace_application_default(self.0.clone());
    }
}

/// Caching must preserve fixed policies and independent transaction budgets.
#[test]
fn test_cached_builtins_keep_policy_and_transaction_contracts() {
    let standard = Redactor::standard();
    let strict = Redactor::strict();
    let previous = Redactor::replace_application_default(Redactor::new(RedactionPolicy::disabled()));
    let _restore = RestoreDefault(previous);
    assert!(Redactor::application_default().policy().is_disabled());
    assert_eq!(Redactor::standard(), standard);
    assert_eq!(Redactor::strict(), strict);
    assert_eq!(Redactor::default(), standard);
    assert_eq!(
        standard.redact_field("unlisted_probe", "visible").text().as_str(),
        "visible",
    );
    assert_eq!(
        strict.redact_field("unlisted_probe", "visible").text().as_str(),
        "<redacted>",
    );
    for constructor in [Redactor::standard as fn() -> Redactor, Redactor::strict] {
        let first = constructor().redact_field("password", "raw-secret");
        let second = constructor().redact_field("password", "raw-secret");
        assert_eq!(first.text().as_str(), "<redacted>");
        assert_eq!(first.text().as_str(), second.text().as_str());
        assert_eq!(first.summary(), second.summary());
    }
}
