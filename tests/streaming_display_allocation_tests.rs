// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Allocation regressions for bounded redacted display.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write;
use std::sync::Mutex;

use qubit_redact::Redact;
use qubit_redact::RedactedMap;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
/// Serializes allocation-counting sections within this integration-test binary.
static TEST_LOCK: Mutex<()> = Mutex::new(());
/// Small allocation-count ceiling for eager bounded display completion.
const MAX_BOUNDED_DISPLAY_ALLOCATIONS: usize = 8;
thread_local! {
    /// Controls allocation tracking for the current measurement thread.
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    /// Counts allocations performed by the current measurement thread.
    static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
}

/// Global allocator that can count a narrowly scoped formatting operation.
struct CountingAllocator;

// SAFETY: Every operation delegates to `System` with the original layout and
// pointer. The additional atomics do not alter allocator contracts.
unsafe impl GlobalAlloc for CountingAllocator {
    /// Allocates memory through the system allocator and records the call.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: `layout` is forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    /// Deallocates memory through the system allocator.
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from the delegated allocator.
        unsafe { System.dealloc(pointer, layout) }
    }

    /// Allocates zeroed memory through the system allocator and records it.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: `layout` is forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    /// Resizes an allocation through the system allocator and records it.
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: All arguments are forwarded unchanged to the system
        // allocator.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

/// Records one allocation when a test measurement is active.
#[inline(always)]
fn record_allocation() {
    TRACK_ALLOCATIONS.with(|tracking| {
        if tracking.get() {
            ALLOCATION_COUNT.with(|count| count.set(count.get() + 1));
        }
    });
}

/// Fixed-capacity formatting destination that never allocates.
struct FixedBuffer {
    /// Stack storage for formatted bytes.
    bytes: [u8; 512],
    /// Number of initialized bytes.
    len: usize,
}

impl FixedBuffer {
    /// Creates an empty stack-backed destination.
    #[must_use]
    const fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
        }
    }
}

impl Write for FixedBuffer {
    /// Appends text when it fits in the remaining stack storage.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.saturating_add(value.len());
        if end > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Domain value whose redacted representation contains only safe text.
struct SafeRecord {
    /// Visible identifier.
    id: u64,
    /// Visible safe diagnostic label.
    label: &'static str,
}

impl Redact for SafeRecord {
    /// Writes the safe diagnostic representation.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter
            .debug_struct("SafeRecord")
            .field("id", &self.id)
            .field("label", &self.label)
            .finish()
    }
}

/// Measures one formatting closure after all fixtures are prepared.
///
/// # Parameters
///
/// * `format` - Formatting operation whose allocations are counted.
///
/// # Returns
///
/// The number of allocation or reallocation calls during `format`.
fn measured_allocations(format: impl FnOnce()) -> usize {
    let _guard = TEST_LOCK.lock().expect("the allocation test lock is valid");
    ALLOCATION_COUNT.with(|count| count.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    format();
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    ALLOCATION_COUNT.with(Cell::get)
}

/// Verifies redacted domain and empty-map views use only bounded buffering.
#[test]
fn test_redacted_displays_use_bounded_allocation_count() {
    let record = SafeRecord {
        id: 7,
        label: "visible",
    };
    let view = record.redacted();
    let mut output = FixedBuffer::new();

    let allocations = measured_allocations(|| {
        write!(&mut output, "{view}").expect("the fixed output buffer can hold the record");
    });

    assert!(allocations <= MAX_BOUNDED_DISPLAY_ALLOCATIONS);
    let map = BTreeMap::<&str, &str>::new();
    let view = RedactedMap::new(&map, RedactionPolicy::default());
    let mut output = FixedBuffer::new();

    let allocations = measured_allocations(|| {
        write!(&mut output, "{view}").expect("the fixed output buffer can hold the map");
    });

    assert!(allocations <= MAX_BOUNDED_DISPLAY_ALLOCATIONS);
}

/// Verifies a visible nonempty map stays within the bounded allocation count.
#[test]
fn test_nonempty_redacted_map_uses_bounded_allocation_count() {
    let map = BTreeMap::from([("visible", "safe")]);
    let policy = RedactionPolicy::builder()
        .allow_canonical_exact("visible")
        .expect("the test builder input should be valid")
        .build()
        .expect("the visible-field policy should be valid");
    let view = RedactedMap::new(&map, policy);
    let mut output = FixedBuffer::new();

    let allocations = measured_allocations(|| {
        write!(&mut output, "{view}").expect("the fixed output buffer can hold the visible map");
    });

    assert!(allocations <= MAX_BOUNDED_DISPLAY_ALLOCATIONS);
}
