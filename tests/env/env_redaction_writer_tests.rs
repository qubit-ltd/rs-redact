// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use std::ffi::OsStr;

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

/// Exact-size iterator that exposes the capacity-allocation bug without
/// materializing a huge environment collection.
struct HugeEnvironmentIterator {
    remaining: usize,
}

impl Iterator for HugeEnvironmentIterator {
    type Item = (&'static OsStr, &'static OsStr);

    /// Returns one repeated non-sensitive assignment until exhausted.
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some((OsStr::new("FIRST"), OsStr::new("visible")))
    }

    /// Reports the exact remaining length without allocating the suffix.
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for HugeEnvironmentIterator {
    /// Returns the iterator's exact remaining item count.
    fn len(&self) -> usize {
        self.remaining
    }
}

#[test]
fn session_environment_operations_share_aggregate_and_handle_transaction_output() {
    let redactor = Redactor::standard();
    let mut session = redactor.session();
    session.env(|env| {
        env.pair("MODE", "debug");
        env.os_pairs([(OsStr::new("REGION"), OsStr::new("ap-east-1"))]);
    });
    let password = session.redact_env("PASSWORD", "raw-secret");
    let output = session.finish();

    assert_eq!(output.text().as_str(), r#"MODE=debug["REGION=ap-east-1"]"#,);
    assert_eq!(
        output
            .resolve(password)
            .expect("handle belongs to the committed transaction")
            .text()
            .as_str(),
        "PASSWORD=<redacted>",
    );
    assert_eq!(
        output
            .resolve(password)
            .expect("handle belongs to the committed transaction")
            .summary()
            .completion(),
        RedactionCompletion::Complete
    );
}

#[test]
fn session_environment_pair_and_handle_share_one_output_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(10);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    session.env(|env| {
        env.pair("MODE", "debug");
    });
    let password = session.redact_env("PASSWORD", "raw-secret");
    let output = session.finish();

    assert_eq!(output.text().as_str(), "MODE=debug");
    let password = output
        .resolve(password)
        .expect("handle belongs to the committed transaction");
    assert!(password.text().as_str().is_empty());
    assert_eq!(password.summary().completion(), RedactionCompletion::Exhausted);
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert_eq!(output.summary().usage().output_bytes(), 10);
}

#[test]
fn session_environment_os_pair_handle_publishes_after_finish() {
    let mut session = Redactor::standard().session();
    let handle = session.redact_env_pairs([
        (OsStr::new("REGION"), OsStr::new("ap-east-1")),
        (OsStr::new("PASSWORD"), OsStr::new("raw-secret")),
    ]);
    let output = session.finish();

    let item = output
        .resolve(handle)
        .expect("environment handle should publish after finish");
    assert!(item.text().as_str().contains("REGION=ap-east-1"));
    assert!(!item.text().as_str().contains("raw-secret"));
}

/// An explicit environment pair must use runtime classification in both the
/// aggregate and staged-handle paths, without exposing the sensitive value.
#[test]
fn session_environment_aggregate_and_handle_mask_classified_value() {
    let mut session = Redactor::strict().session();
    session.env(|env| {
        env.pair("PASSWORD", "aggregate-secret");
    });
    let handle = session.redact_env("PASSWORD", "handle-secret");
    let output = session.finish();
    let item = output.resolve(handle).expect("environment handle publishes");

    assert!(!output.text().as_str().contains("aggregate-secret"));
    assert!(!item.text().as_str().contains("handle-secret"));
    assert_eq!(item.summary().completion(), RedactionCompletion::Complete);
}

/// Environment list traversal must fail closed at the common collection
/// ledger, rather than partially rendering an admitted prefix independently.
#[test]
fn session_environment_list_handle_stops_at_collection_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();
    let handle = session.redact_env_pairs([
        (OsStr::new("FIRST"), OsStr::new("visible")),
        (OsStr::new("PASSWORD"), OsStr::new("must-not-be-rendered")),
    ]);
    let output = session.finish();
    let item = output.resolve(handle).expect("truncated environment handle publishes");

    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert!(!item.text().as_str().contains("must-not-be-rendered"));
}

/// The collection limit must protect the runtime before a collection's
/// advertised exact length influences allocation.
#[test]
fn environment_handle_does_not_preallocate_from_unadmitted_iterator_length() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();
    let handle = session.redact_env_pairs(HugeEnvironmentIterator { remaining: usize::MAX });
    let output = session.finish();
    let item = output.resolve(handle).expect("environment handle publishes");

    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
}
