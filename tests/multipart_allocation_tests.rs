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

use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
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
                ALLOCATED.with(|allocated| allocated.set(allocated.get().saturating_add(bytes)));
            }
        });
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure<T>(operation: impl FnOnce() -> T) -> (usize, T) {
    ALLOCATED.with(|allocated| allocated.set(0));
    COUNTING.with(|counting| counting.set(true));
    let result = operation();
    COUNTING.with(|counting| counting.set(false));
    (ALLOCATED.with(Cell::get), result)
}

fn multipart(parts: usize) -> Vec<u8> {
    let part = b"--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nv\r\n";
    let mut body = Vec::with_capacity(parts.saturating_mul(part.len()).saturating_add(7));
    for _ in 0..parts {
        body.extend_from_slice(part);
    }
    body.extend_from_slice(b"--b--\r\n");
    body
}

fn policy(max_collection_items: usize) -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_input_bytes(10_000_000)
                .max_collection_items(max_collection_items);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build")
}

#[test]
fn test_multipart_auxiliary_allocations_do_not_scale_with_unadmitted_parts() {
    let small = multipart(4_096);
    let large = multipart(32_768);
    let mut measurements = Vec::new();
    for (part_count, body) in [(4_096, &small), (32_768, &large)] {
        for collection_limit in [0, 1] {
            let redactor = Redactor::new(policy(collection_limit));
            let _ = redactor.inspect_http_body_with_content_type_text(
                BodyCapture::complete(body),
                Some("multipart/form-data; boundary=b"),
            );
            for operation in ["inspection", "rendering"] {
                let (allocated, rejected) = if operation == "inspection" {
                    measure(|| {
                        redactor
                            .inspect_http_body_with_content_type_text(
                                BodyCapture::complete(body),
                                Some("multipart/form-data; boundary=b"),
                            )
                            .is_err()
                    })
                } else {
                    measure(|| {
                        redactor
                            .redact_http_body_with_content_type_text(
                                BodyCapture::complete(body),
                                Some("multipart/form-data; boundary=b"),
                            )
                            .summary()
                            .reasons()
                            .contains(RedactionReason::TraversalLimitReached)
                    })
                };
                assert!(
                    rejected,
                    "size={} limit={collection_limit} operation={operation} was accepted",
                    body.len()
                );
                measurements.push((part_count, body.len(), collection_limit, operation, allocated));
            }
        }
    }
    for (part_count, size, limit, operation, allocated) in &measurements {
        assert!(
            *allocated < 65_536,
            "N={part_count} body_bytes={size} limit={limit} operation={operation} allocated={allocated} bytes"
        );
    }
    for collection_limit in [0, 1] {
        for operation in ["inspection", "rendering"] {
            let small = measurements
                .iter()
                .find(|(part_count, _, limit, measured_operation, _)| {
                    *part_count == 4_096 && *limit == collection_limit && *measured_operation == operation
                })
                .expect("small allocation measurement exists")
                .4;
            let large = measurements
                .iter()
                .find(|(part_count, _, limit, measured_operation, _)| {
                    *part_count == 32_768 && *limit == collection_limit && *measured_operation == operation
                })
                .expect("large allocation measurement exists")
                .4;
            assert!(
                large <= small.saturating_add(8_192),
                "limit={collection_limit} operation={operation}: N=4096 {small}, N=32768 {large}"
            );
        }
    }
    eprintln!("multipart allocator bytes: {measurements:?}");
}
