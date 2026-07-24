// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Allocation regression tests for streaming redacted display.

use std::{
    alloc::{
        GlobalAlloc,
        Layout,
        System,
    },
    collections::BTreeMap,
    fmt::{
        self,
        Write,
    },
    sync::{
        Mutex,
        atomic::{
            AtomicBool,
            AtomicUsize,
            Ordering,
        },
    },
};

use qubit_redact::{
    Redact,
    RedactedMap,
    RedactionPolicy,
};

/// Serializes allocation-counting sections within this integration-test binary.
static TEST_LOCK: Mutex<()> = Mutex::new(());
/// Controls whether allocator calls contribute to the active measurement.
static TRACK_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
/// Counts allocations performed while tracking is enabled.
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

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
    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        layout: Layout,
        new_size: usize,
    ) -> *mut u8 {
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
    if TRACK_ALLOCATIONS.load(Ordering::Relaxed) {
        ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
    }
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
        _policy: &RedactionPolicy,
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
    ALLOCATION_COUNT.store(0, Ordering::Relaxed);
    TRACK_ALLOCATIONS.store(true, Ordering::Relaxed);
    format();
    TRACK_ALLOCATIONS.store(false, Ordering::Relaxed);
    ALLOCATION_COUNT.load(Ordering::Relaxed)
}

/// Verifies redacted domain and map views stream without heap allocation.
#[test]
fn test_redacted_displays_stream_without_allocation() {
    let record = SafeRecord {
        id: 7,
        label: "visible",
    };
    let view = record.redacted();
    let mut output = FixedBuffer::new();

    let allocations = measured_allocations(|| {
        write!(&mut output, "{view}")
            .expect("the fixed output buffer can hold the record");
    });

    assert_eq!(allocations, 0);
    let map = BTreeMap::<&str, &str>::new();
    let view = RedactedMap::new(&map, RedactionPolicy::default());
    let mut output = FixedBuffer::new();

    let allocations = measured_allocations(|| {
        write!(&mut output, "{view}")
            .expect("the fixed output buffer can hold the map");
    });

    assert_eq!(allocations, 0);
}
