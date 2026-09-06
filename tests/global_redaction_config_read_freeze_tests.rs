// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Concurrency regression tests for application-default snapshots.

use std::sync::Arc;
use std::sync::Barrier;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
/// Verifies concurrent reads observe complete snapshots while replacements
/// leave an earlier read unchanged.
#[test]
fn test_concurrent_application_default_reads_observe_complete_snapshots() {
    let before_application_default = Redactor::application_default();
    let before_standard = Redactor::default();
    let strict = Redactor::strict();
    let standard = Redactor::standard();
    let barrier = Arc::new(Barrier::new(2));

    let reader_barrier = Arc::clone(&barrier);
    let reader = std::thread::spawn(move || {
        reader_barrier.wait();
        (0..1_000)
            .map(|_| Redactor::application_default())
            .collect::<Vec<_>>()
    });

    let initial_previous = Redactor::replace_application_default(standard.clone());
    barrier.wait();
    for index in 0..1_000 {
        let replacement = if index % 2 == 0 {
            strict.clone()
        } else {
            standard.clone()
        };
        let _ = Redactor::replace_application_default(replacement);
    }

    let observed = reader.join().expect("reader thread must not panic");
    for snapshot in observed {
        assert!(snapshot == standard || snapshot == strict);
    }

    assert_eq!(before_standard, Redactor::default());
    assert_eq!(
        RedactionPolicy::builder()
            .build()
            .expect("the deterministic builder should remain valid"),
        RedactionPolicy::standard(),
    );

    let _ = Redactor::replace_application_default(initial_previous);
    assert_eq!(Redactor::application_default(), before_application_default);
}
