// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Allocation regressions for bounded core redaction diagnostics.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use qubit_redact::InputOutputLimit;
use qubit_redact::LogOutputLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::Redact;
use qubit_redact::RedactedMap;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
#[cfg(feature = "uri")]
use qubit_redact::UriRedactor;
use qubit_redact::argv::ArgvItem;
use qubit_redact::argv::ArgvRedactor;
use qubit_redact::env::EnvRedactor;
/// Serializes allocation measurements inside this integration-test binary.
static ALLOCATION_TEST_LOCK: Mutex<()> = Mutex::new(());
thread_local! {
    /// Enables recording only for the current measurement thread.
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
}
/// Records the largest allocation or reallocation during a measurement.
static LARGEST_ALLOCATION: AtomicUsize = AtomicUsize::new(0);

/// Global allocator that records allocation sizes for focused regressions.
struct MeasuringAllocator;

// SAFETY: Every operation delegates unchanged to `System`; recording sizes
// does not modify allocation contracts.
unsafe impl GlobalAlloc for MeasuringAllocator {
    /// Allocates through `System` while optionally recording the request size.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: The layout is forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    /// Deallocates through `System` without recording a new allocation.
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The original pointer and layout are forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }

    /// Allocates zeroed memory through `System` while recording the request.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: The layout is forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    /// Resizes memory through `System` while recording the new request size.
    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        layout: Layout,
        new_size: usize,
    ) -> *mut u8 {
        record_allocation(new_size);
        // SAFETY: The original pointer, layout, and new size are forwarded.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: MeasuringAllocator = MeasuringAllocator;

/// Records a request size only while one measurement is active.
#[inline(always)]
fn record_allocation(size: usize) {
    if TRACK_ALLOCATIONS.with(Cell::get) {
        LARGEST_ALLOCATION.fetch_max(size, Ordering::Relaxed);
    }
}

/// Runs one operation and reports its largest allocation request.
///
/// # Parameters
///
/// * `operation` - Operation to measure after fixtures are prepared.
///
/// # Returns
///
/// The operation result and largest requested allocation size.
fn measure_largest_allocation<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    LARGEST_ALLOCATION.store(0, Ordering::Relaxed);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = operation();
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    (result, LARGEST_ALLOCATION.load(Ordering::Relaxed))
}

/// Acquires the local measurement lock after recovering from an expected test
/// failure.
///
/// # Returns
///
/// The mutex guard that serializes allocation measurements in this test binary.
fn allocation_test_lock() -> MutexGuard<'static, ()> {
    ALLOCATION_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Stack-backed formatting destination that avoids measuring caller output.
struct FixedBuffer {
    /// Backing bytes for one bounded diagnostic rendering.
    bytes: [u8; 512],
    /// Number of initialized output bytes.
    len: usize,
}

impl FixedBuffer {
    /// Creates an empty stack-backed formatting destination.
    const fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
        }
    }
}

impl Write for FixedBuffer {
    /// Writes text when it fits into the fixed destination.
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

/// Builds a policy whose fixed sensitive replacement is deliberately large.
fn amplified_policy() -> RedactionPolicy {
    let replacement = "X".repeat(1024 * 1024);
    let budget = InputOutputLimit::new(4096, 128)
        .expect("the diagnostic budget should be valid");
    RedactionPolicy::builder()
        .mask(Sensitivity::High, MaskPolicy::fixed(&replacement))
        .expect("the test mask policy should be valid")
        .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
        .expect("the test mask policy should be valid")
        .diagnostic_event(budget)
        .build()
        .expect("the amplified policy should be valid")
}

/// Redacted value that renders a bounded map inside an outer bounded view.
struct NestedBoundedMap<'a> {
    /// Sensitive values rendered by the inner map.
    values: &'a BTreeMap<&'a str, &'a str>,
    /// Policy containing an amplified fixed mask.
    policy: RedactionPolicy,
    /// Output limit requested by the inner bounded view.
    limit: LogOutputLimit,
}

impl Redact for NestedBoundedMap<'_> {
    /// Renders the inner map with its independently requested output limit.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(
            formatter,
            "{}",
            RedactedMap::new(self.values, self.policy.clone())
                .with_output_limit(self.limit),
        )
    }
}

/// Verifies an inner bounded view cannot widen the outer mask allocation
/// ceiling.
#[test]
fn test_nested_bounded_display_does_not_widen_mask_allocation_limit() {
    let _guard = allocation_test_lock();
    let values = BTreeMap::from([("password", "raw-secret")]);
    let inner_limit = LogOutputLimit::new(2 * 1024 * 1024)
        .expect("the inner output limit should be valid");
    let outer_limit = LogOutputLimit::new(14)
        .expect("the outer output limit should be valid");
    let nested = NestedBoundedMap {
        values: &values,
        policy: amplified_policy(),
        limit: inner_limit,
    };
    let view = nested.redacted().with_output_limit(outer_limit);
    let mut output = FixedBuffer::new();

    let (result, largest) =
        measure_largest_allocation(|| write!(&mut output, "{view}"));

    result.expect("the nested bounded view should fit the fixed output buffer");
    assert!(
        largest < 4096,
        "inner bounded view widened the mask allocation limit: {largest}",
    );
}

/// Verifies a bounded map view never materializes a full fixed mask.
#[test]
fn test_bounded_redacted_map_avoids_amplified_mask_allocation() {
    let _guard = allocation_test_lock();
    let values = BTreeMap::from([("password", "raw-secret")]);
    let limit = LogOutputLimit::new(128)
        .expect("the test output limit should be valid");
    let view =
        RedactedMap::new(&values, amplified_policy()).with_output_limit(limit);
    let mut output = FixedBuffer::new();

    let (result, largest) =
        measure_largest_allocation(|| write!(&mut output, "{view}"));

    result.expect("the bounded map should fit the fixed output buffer");
    assert!(
        largest < 4096,
        "bounded map copied an amplified mask: {largest}"
    );
}

/// Verifies bounded argv diagnostics never materialize a full fixed mask.
#[test]
fn test_bounded_argv_avoids_amplified_mask_allocation() {
    let _guard = allocation_test_lock();
    let redactor = ArgvRedactor::new(Redactor::new(amplified_policy()));

    let (rendered, largest) = measure_largest_allocation(|| {
        redactor
            .redact_items([ArgvItem::sensitive(
                OsStr::new("raw-secret"),
                Sensitivity::Secret,
            )])
            .to_string()
    });

    assert!(rendered.len() <= 128, "{rendered}");
    assert!(
        largest < 4096,
        "bounded argv copied an amplified mask: {largest}"
    );
}

/// Verifies bounded environment diagnostics never materialize a full fixed
/// mask.
#[test]
fn test_bounded_environment_avoids_amplified_mask_allocation() {
    let _guard = allocation_test_lock();
    let redactor = EnvRedactor::new(Redactor::new(amplified_policy()));

    let (rendered, largest) = measure_largest_allocation(|| {
        redactor
            .redact_os_pairs([(
                OsStr::new("PASSWORD"),
                OsStr::new("raw-secret"),
            )])
            .to_string()
    });

    assert!(rendered.len() <= 128, "{rendered}");
    assert!(
        largest < 4096,
        "bounded environment copied an amplified mask: {largest}",
    );
}

/// Verifies URI rendering never materializes one amplified mask per query.
#[cfg(feature = "uri")]
#[test]
fn test_bounded_uri_avoids_amplified_mask_allocation() {
    let _guard = allocation_test_lock();
    let replacement = "X".repeat(1024 * 1024);
    let budget = InputOutputLimit::new(4096, 128)
        .expect("the diagnostic budget should be valid");
    let core = RedactionPolicy::default()
        .to_builder()
        .mask(Sensitivity::High, MaskPolicy::fixed(&replacement))
        .expect("the high mask policy should be valid")
        .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
        .expect("the secret mask policy should be valid")
        .diagnostic_event(budget)
        .build()
        .expect("the core policy should be valid");
    let uri_policy = RedactionPolicy::builder_from(&core)
        .build()
        .expect("the URI policy should be valid");
    let redactor = UriRedactor::new(uri_policy);
    let query = ["password=query-secret"; 32].join("&");
    let input = format!("https://user:password@example.test/?{query}#fragment");

    let (result, largest) =
        measure_largest_allocation(|| redactor.redact_uri_str(&input));

    assert!(result.is_truncated());
    assert!(result.log_safe_text().as_ref().len() <= 128);
    assert!(
        largest <= 4096,
        "URI redaction copied an amplified mask: {largest}",
    );
}
