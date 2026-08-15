// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use std::cell::Cell;
use std::ffi::OsStr;

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

struct CountingPairs<'count> {
    pulls: &'count Cell<usize>,
}

impl Iterator for CountingPairs<'_> {
    type Item = (&'static OsStr, &'static OsStr);

    fn next(&mut self) -> Option<Self::Item> {
        self.pulls.set(self.pulls.get() + 1);
        Some((OsStr::new("NAME"), OsStr::new("unread-secret")))
    }
}

/// Verifies that a terminal session does not pull a second environment pair.
#[test]
fn test_env_session_does_not_pull_iterator_after_output_exhaustion() {
    let limit = InputOutputLimit::new(1, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the marker-sized diagnostic limit should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(limit)
        .build()
        .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let pulls = Cell::new(0);
    let _ = session
        .env()
        .redact_os_pairs(CountingPairs { pulls: &pulls });
    let pulls_after_exhaustion = pulls.get();
    let _ = session
        .env()
        .redact_os_pairs(CountingPairs { pulls: &pulls });
    assert_eq!(pulls.get(), pulls_after_exhaustion);
}
