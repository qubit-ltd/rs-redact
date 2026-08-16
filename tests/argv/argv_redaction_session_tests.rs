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
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::argv::ArgvItem;
use qubit_redact::argv::RedactedArgv;

struct CountingItems<'count> {
    pulls: &'count Cell<usize>,
}

/// Compile-checks the stable value traits of a public result type.
fn assert_result_traits<T: Clone + std::fmt::Debug + Eq>() {}

impl Iterator for CountingItems<'_> {
    type Item = ArgvItem<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        self.pulls.set(self.pulls.get() + 1);
        Some(ArgvItem::plain(OsStr::new("unread-secret")))
    }
}

/// Verifies a fully rendered argv reports complete output.
#[test]
fn test_argv_session_reports_complete_output() {
    assert_result_traits::<RedactedArgv>();
    let redactor = Redactor::default();
    let mut session = redactor.session();

    let result = session
        .argv()
        .redact_items([ArgvItem::plain(OsStr::new("client"))]);

    assert_eq!(result.completion(), RedactionCompletion::Complete);
    assert_eq!(result.log_safe_text().as_str(), r#"["client"]"#);
    assert_eq!(result.into_log_safe_text().as_str(), r#"["client"]"#);
}

/// Verifies exact input exhaustion reports omitted trailing items without
/// pulling the second item.
#[test]
fn test_argv_session_reports_truncated_when_input_ends_before_iterator() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(1)
        .max_output_bytes(64)
        .build()
        .expect("the exact input limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let pulls = Cell::new(0);
    let items = std::iter::from_fn(|| {
        pulls.set(pulls.get() + 1);
        Some(ArgvItem::plain(OsStr::new("a")))
    });

    let result = session.argv().redact_items(items);

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(!result.log_safe_text().as_str().is_empty());
    assert_eq!(pulls.get(), 1);
}

/// Verifies an input-rejection marker reports non-empty truncated output.
#[test]
fn test_argv_session_reports_truncated_marker() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(1)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the marker-sized diagnostic limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let result = session
        .argv()
        .redact_heuristically([ArgvItem::plain(OsStr::new("secret"))]);

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(!result.log_safe_text().as_str().is_empty());
}

/// Verifies a locally shortened mask reports truncation even when the escaped
/// list itself fits exactly.
#[test]
fn test_argv_session_reports_local_mask_truncation() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(64)
        .max_output_bytes(64)
        .build()
        .expect("the exact-fit diagnostic limit should be valid");
    let replacement = "💥".repeat(64);
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
            .expect("the oversized secret mask should be valid");
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let result = session.argv().redact_items([ArgvItem::sensitive(
        OsStr::new("secret"),
        Sensitivity::Secret,
    )]);

    assert_eq!(result.log_safe_text().as_str().len(), 64);
    assert_eq!(result.completion(), RedactionCompletion::Truncated);
}

/// Verifies exhausted argv output is empty and does not advance its iterator.
#[test]
fn test_argv_session_reports_exhausted_without_advancing_iterator() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(1)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the marker-sized diagnostic limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let _ = session
        .argv()
        .redact_heuristically([ArgvItem::plain(OsStr::new("secret"))]);
    let pulls = Cell::new(0);

    let result = session
        .argv()
        .redact_heuristically(CountingItems { pulls: &pulls });

    assert_eq!(result.completion(), RedactionCompletion::Exhausted);
    assert_eq!(result.log_safe_text().as_str(), "");
    assert_eq!(pulls.get(), 0);
}

/// Verifies list delimiters are included in shared output accounting.
#[test]
fn test_argv_session_charges_delimiters_across_following_operations() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(128)
        .max_output_bytes(64)
        .build()
        .expect("the diagnostic limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let argv = session
        .argv()
        .redact_items([ArgvItem::plain(OsStr::new("client"))])
        .to_string();
    let env = session.env().redact_pair("MODE", "debug").to_string();

    assert_eq!(
        session.remaining_output_bytes(),
        limit.max_output_bytes() - argv.len() - env.len()
    );
}
