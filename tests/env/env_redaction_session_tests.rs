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
use qubit_redact::formats::env::RedactedEnv;
use qubit_redact::formats::env::RedactedEnvPair;

struct CountingPairs<'count> {
    pulls: &'count Cell<usize>,
}

/// Compile-checks the stable value traits of a public result type.
fn assert_result_traits<T: Clone + std::fmt::Debug + Eq>() {}

impl Iterator for CountingPairs<'_> {
    type Item = (&'static OsStr, &'static OsStr);

    fn next(&mut self) -> Option<Self::Item> {
        self.pulls.set(self.pulls.get() + 1);
        Some((OsStr::new("NAME"), OsStr::new("unread-secret")))
    }
}

/// Verifies a fully rendered environment pair reports complete output.
#[test]
fn test_env_pair_session_reports_complete_output() {
    assert_result_traits::<RedactedEnvPair>();
    assert_result_traits::<RedactedEnv>();
    let redactor = Redactor::default();
    let mut session = redactor.session();

    let result = session.env().redact_pair("MODE", "debug");

    assert_eq!(result.completion(), RedactionCompletion::Complete);
    assert_eq!(result.log_safe_text().as_str(), "MODE=debug");
    assert_eq!(result.into_log_safe_text().as_str(), "MODE=debug");
}

/// Verifies a locally shortened multibyte mask reports pair truncation when
/// the complete escaped assignment still fits the remaining output exactly.
#[test]
fn test_env_pair_session_reports_local_mask_truncation() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(64)
        .max_output_bytes(64)
        .build()
        .expect("the exact-fit diagnostic limit should be valid");
    let replacement = "💥".repeat(64);
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .legacy_fields()
            .raise("a", Sensitivity::Secret)
            .expect("the short sensitive field should be valid");
        builder
            .legacy_fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
            .expect("the oversized secret mask should be valid");
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let _ = session.argv().redact_items(std::iter::empty());

    let result = session.env().redact_pair("a", "secret");

    assert_eq!(result.log_safe_text().as_str().len(), 62);
    assert_eq!(result.completion(), RedactionCompletion::Truncated);
}

/// Verifies an input-rejection pair reports non-empty truncated output.
#[test]
fn test_env_pair_session_reports_truncated_fallback() {
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

    let result = session.env().redact_pair("PASSWORD", "secret");

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(!result.log_safe_text().as_str().is_empty());
}

/// Verifies an exhausted environment pair reports empty output.
#[test]
fn test_env_pair_session_reports_exhausted_output() {
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
    let _ = session.env().redact_pair("PASSWORD", "secret");

    let result = session.env().redact_pair("PASSWORD", "secret");

    assert_eq!(result.completion(), RedactionCompletion::Exhausted);
    assert_eq!(result.log_safe_text().as_str(), "");
}

/// Verifies a fully rendered environment batch reports complete output.
#[test]
fn test_env_batch_session_reports_complete_output() {
    let redactor = Redactor::default();
    let mut session = redactor.session();

    let result = session
        .env()
        .redact_os_pairs([(OsStr::new("MODE"), OsStr::new("debug"))]);

    assert_eq!(result.completion(), RedactionCompletion::Complete);
    assert_eq!(result.log_safe_text().as_str(), r#"["MODE=debug"]"#);
    assert_eq!(result.into_log_safe_text().as_str(), r#"["MODE=debug"]"#);
}

/// Verifies exact input exhaustion reports omitted trailing pairs without
/// pulling the second pair.
#[test]
fn test_env_batch_session_reports_truncated_when_input_ends_before_iterator() {
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
    let pairs = std::iter::from_fn(|| {
        pulls.set(pulls.get() + 1);
        Some((OsStr::new(""), OsStr::new("a")))
    });

    let result = session.env().redact_os_pairs(pairs);

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(!result.log_safe_text().as_str().is_empty());
    assert_eq!(pulls.get(), 1);
}

/// Verifies an input-rejection batch reports non-empty truncated output.
#[test]
fn test_env_batch_session_reports_truncated_marker() {
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
        .env()
        .redact_os_pairs([(OsStr::new("PASSWORD"), OsStr::new("secret"))]);

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(!result.log_safe_text().as_str().is_empty());
}

/// Verifies exhausted batch output is empty and does not advance its iterator.
#[test]
fn test_env_batch_session_reports_exhausted_without_advancing_iterator() {
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
        .env()
        .redact_os_pairs([(OsStr::new("PASSWORD"), OsStr::new("secret"))]);
    let pulls = Cell::new(0);

    let result = session
        .env()
        .redact_os_pairs(CountingPairs { pulls: &pulls });

    assert_eq!(result.completion(), RedactionCompletion::Exhausted);
    assert_eq!(result.log_safe_text().as_str(), "");
    assert_eq!(pulls.get(), 0);
}
