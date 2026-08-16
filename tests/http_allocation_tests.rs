// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Allocation regressions for bounded HTTP diagnostics.

#![cfg(feature = "http")]

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::formats::http::BodyBudget;
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::http::HttpRedactor;
use qubit_redact::formats::http::InputOutputLimit;
thread_local! {
    /// Controls whether the current thread contributes to a measurement.
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
}
/// Records the largest allocation or reallocation while tracking is enabled.
static LARGEST_ALLOCATION: AtomicUsize = AtomicUsize::new(0);
/// Counts allocations and reallocations while tracking is enabled.
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Serializes tests that share process-global allocation counters.
static ALLOCATION_TEST_LOCK: Mutex<()> = Mutex::new(());
/// Maximum HTTP-redaction allocations beyond parsing the same JSON body.
const MAX_UNKEYED_REDACTION_ALLOCATION_OVERHEAD: usize = 32;

/// Global allocator that records the largest narrowly scoped allocation.
struct MeasuringAllocator;

// SAFETY: Every operation delegates to `System` with the original layout and
// pointer. Recording allocation sizes does not alter allocator contracts.
unsafe impl GlobalAlloc for MeasuringAllocator {
    /// Allocates memory through the system allocator and records its size.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
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
        record_allocation(layout.size());
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
        record_allocation(new_size);
        // SAFETY: All arguments are forwarded unchanged to the system
        // allocator.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: MeasuringAllocator = MeasuringAllocator;

/// Records an allocation size when a measurement is active.
///
/// # Parameters
///
/// * `size` - Requested allocation or reallocation size.
#[inline(always)]
fn record_allocation(size: usize) {
    if TRACK_ALLOCATIONS.with(Cell::get) {
        LARGEST_ALLOCATION.fetch_max(size, Ordering::Relaxed);
        ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Measures the largest allocation made by one operation.
///
/// # Parameters
///
/// * `operation` - Operation whose allocations are measured.
///
/// # Returns
///
/// The operation result, largest requested size, and allocation count.
fn measure_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize, usize) {
    LARGEST_ALLOCATION.store(0, Ordering::Relaxed);
    ALLOCATION_COUNT.store(0, Ordering::Relaxed);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = operation();
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    (
        result,
        LARGEST_ALLOCATION.load(Ordering::Relaxed),
        ALLOCATION_COUNT.load(Ordering::Relaxed),
    )
}

/// Verifies one measurement ignores allocations from a coordinated worker.
#[test]
fn test_measure_allocations_ignores_other_threads() {
    let _lock = ALLOCATION_TEST_LOCK
        .lock()
        .expect("allocation measurement lock should not be poisoned");
    let measurement_started = Arc::new(AtomicBool::new(false));
    let worker_finished = Arc::new(AtomicBool::new(false));
    let worker_measurement_started = Arc::clone(&measurement_started);
    let worker_finished_signal = Arc::clone(&worker_finished);
    let worker = std::thread::spawn(move || {
        while !worker_measurement_started.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let allocation = vec![0_u8; 8192];
        std::hint::black_box(&allocation);
        worker_finished_signal.store(true, Ordering::Release);
    });

    let (_, largest, count) = measure_allocations(|| {
        measurement_started.store(true, Ordering::Release);
        while !worker_finished.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
    });
    worker.join().expect("the worker thread should not panic");

    assert_eq!(largest, 0, "worker allocation polluted this measurement");
    assert_eq!(count, 0, "worker allocation polluted this measurement");
}

/// Verifies HTTP diagnostic allocations follow the rendered output budget.
#[test]
fn test_http_diagnostic_allocations_follow_rendered_output_budget() {
    let _lock = ALLOCATION_TEST_LOCK
        .lock()
        .expect("allocation measurement lock should not be poisoned");
    let redactor = HttpRedactor::default();

    let (result, largest, _) = measure_allocations(|| {
        redactor.redact_url_str("https://example.test/")
    });

    assert_eq!(result.as_ref(), "https://example.test/");
    assert!(
        largest < InputOutputLimit::default().max_output_bytes(),
        "largest allocation unexpectedly reserved the output ceiling: {largest}",
    );

    let json_type = HeaderValue::from_static("application/json");
    let (body, body_largest, _) = measure_allocations(|| {
        redactor.redact_body(
            BodyCapture::complete(br#"{"password":"body-secret"}"#),
            Some(&json_type),
        )
    });
    assert!(!body.to_string().contains("body-secret"));
    assert!(
        body_largest < BodyBudget::default().max_output_bytes(),
        "short body mask reserved the output ceiling: {body_largest}",
    );
    let unsafe_text = "\n".repeat(128);
    let (escaped, _, escape_allocations) =
        measure_allocations(|| redactor.redact_urls_in_text(&unsafe_text));
    assert!(!escaped.as_ref().contains('\n'));
    assert!(
        escape_allocations < 64,
        "control escaping allocated per character: {escape_allocations}",
    );

    let replacement = "X".repeat(1024 * 1024);
    let amplified_policy = ({
        let mut builder = RedactionPolicy::default().to_builder();
        builder
            .fields()
            .mask(Sensitivity::High, MaskPolicy::fixed(&replacement))
            .expect("the test mask policy should be valid");
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the amplified redaction policy is valid");
    let output_limit = 128;
    let diagnostic_budget = InputOutputLimit::builder()
        .max_input_bytes(4096)
        .max_output_bytes(output_limit)
        .build()
        .expect("the diagnostic budget can contain every marker");
    let mut builder = amplified_policy.to_builder();
    builder.limits().diagnostic_event(diagnostic_budget);
    let policy = builder.build().expect("the amplified HTTP policy is valid");
    let redactor = HttpRedactor::new(policy);
    let repeated_form = ["password=form-secret"; 32].join("&");
    let repeated_query = ["password=query-secret"; 32].join("&");
    let repeated_url = format!(
        "https://user:password@example.test/?{repeated_query}#fragment",
    );
    let mut sensitive_header = HeaderValue::from_static("header-secret");
    sensitive_header.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert("x-secret", sensitive_header);

    let (url, url_largest, _) =
        measure_allocations(|| redactor.redact_url_str(&repeated_url));
    let (form, form_largest, _) =
        measure_allocations(|| redactor.redact_form(&repeated_form));
    let (headers, header_largest, _) =
        measure_allocations(|| redactor.redact_headers(&headers));

    for rendered in [url.as_ref(), form.as_ref(), &headers.to_string()] {
        assert!(rendered.len() <= output_limit, "{rendered:?}");
        assert!(rendered.ends_with("<truncated>"), "{rendered:?}");
        for source_secret in
            ["query-secret", "form-secret", "header-secret", "fragment"]
        {
            assert!(!rendered.contains(source_secret), "{rendered:?}");
        }
    }
    for largest in [url_largest, form_largest, header_largest] {
        assert!(
            largest <= 4096,
            "bounded diagnostic copied an amplified mask: {largest}",
        );
    }
}

/// Verifies structured JSON shares one mask budget across every sensitive key.
#[test]
fn test_structured_json_does_not_amplify_fixed_masks_per_field() {
    let _lock = ALLOCATION_TEST_LOCK
        .lock()
        .expect("allocation measurement lock should not be poisoned");
    let replacement = "X".repeat(64 * 1024);
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .mask(Sensitivity::High, MaskPolicy::fixed(&replacement))
        .expect("the test mask policy should be valid")
        .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
        .expect("the test mask policy should be valid");
    for index in 0..700 {
        builder
            .fields()
            .raise(&format!("password_{index}"), Sensitivity::Secret)
            .expect("generated amplified body field must be valid");
    }
    let body_policy =
        builder.build().expect("the amplified body policy is valid");
    let output_limit = 64 * 1024;
    let body_budget = BodyBudget::builder()
        .max_input_bytes(128 * 1024)
        .max_output_bytes(output_limit)
        .build()
        .expect("the body budget is valid");
    let mut builder = body_policy.to_builder();
    builder.limits().http_body(body_budget);
    let policy = builder.build().expect("the HTTP policy is valid");
    let redactor = HttpRedactor::new(policy);
    let fields = (0..700)
        .map(|index| format!(r#""password_{index}":"secret""#))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!("{{{fields}}}");
    let content_type = HeaderValue::from_static("application/json");

    let (result, largest, _) = measure_allocations(|| {
        redactor.redact_body(
            BodyCapture::complete(body.as_bytes()),
            Some(&content_type),
        )
    });

    assert!(result.to_string().len() <= output_limit);
    assert!(!result.to_string().contains("secret"));
    assert!(
        largest <= output_limit * 4,
        "structured masks were materialized once per field: {largest}",
    );
}

/// Verifies unkeyed JSON redaction adds bounded work beyond JSON parsing after
/// consuming the shared mask budget.
#[test]
fn test_unkeyed_json_redaction_respects_mask_budget() {
    let _lock = ALLOCATION_TEST_LOCK
        .lock()
        .expect("allocation measurement lock should not be poisoned");
    let scalars = std::iter::repeat_n(r#""raw-unkeyed-secret""#, 256)
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(r#"{{"items":[{scalars}]}}"#);
    let output_limit = BodyBudget::MIN_OUTPUT_BYTES;
    let body_budget = BodyBudget::builder()
        .max_input_bytes(body.len())
        .max_output_bytes(output_limit)
        .build()
        .expect("the body budget is valid");
    let mut builder = RedactionPolicy::builder();
    builder
        .http()
        .body()
        .allow_exact("items")
        .expect("the items field allow rule should be valid");
    builder.limits().http_body(body_budget);
    let policy = builder.build().expect("the HTTP policy is valid");
    let redactor = HttpRedactor::new(policy);
    let content_type = HeaderValue::from_static("application/json");

    let (_, _, parser_allocations) = measure_allocations(|| {
        serde_json::from_slice::<serde_json::Value>(body.as_bytes())
            .expect("the allocation fixture should be valid JSON")
    });
    let (result, _, allocation_count) = measure_allocations(|| {
        redactor.redact_body(
            BodyCapture::complete(body.as_bytes()),
            Some(&content_type),
        )
    });

    assert_eq!(result.to_string(), "<truncated>");
    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(
        !result.to_string().contains("raw-unkeyed-secret"),
        "mask exhaustion must not leak unkeyed scalar values",
    );
    assert!(
        allocation_count
            <= parser_allocations + MAX_UNKEYED_REDACTION_ALLOCATION_OVERHEAD,
        "unkeyed JSON redaction allocations exceeded the parser baseline: parser={parser_allocations}, total={allocation_count}",
    );
}
