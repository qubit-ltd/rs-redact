// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

/// Exact-size iterator that advertises an impractically large remaining
/// length while only its first item can be admitted by the transaction.
struct HugeArgvIterator {
    remaining: usize,
}

impl Iterator for HugeArgvIterator {
    type Item = ArgvItem<'static>;

    /// Returns the next repeated trusted argument until the advertised length
    /// is exhausted.
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(ArgvItem::plain(OsStr::new("first")))
    }

    /// Reports the exact number of remaining items without allocating them.
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for HugeArgvIterator {
    /// Returns the iterator's exact remaining item count.
    fn len(&self) -> usize {
        self.remaining
    }
}

#[test]
fn batch_publishes_argv_handle_only_after_finish() {
    let mut batch = Redactor::standard().batch();
    let handle = batch.redact_argv([ArgvItem::plain(OsStr::new("client"))]);
    let output = batch.finish();

    assert_eq!(
        output
            .resolve(handle)
            .expect("published handle")
            .text()
            .as_str(),
        r#"["client"]"#
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

#[test]
fn aggregate_argv_adapters_append_to_the_same_output() {
    let output = Redactor::standard()
        .text_composer()
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("client"))]);
        })
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("worker"))]);
        })
        .finish();

    assert!(output.text().as_str().contains("client"));
    assert!(output.text().as_str().contains("worker"));
}

/// Heuristic argv rendering must keep the option-value contract while using
/// the same transaction-owned output allowance as surrounding adapters.
#[test]
fn heuristic_argv_masks_pending_secret_value_in_aggregate_transaction() {
    let output = Redactor::strict()
        .text_composer()
        .argv(|argv| {
            argv.heuristic_items([
                ArgvItem::plain(OsStr::new("--password")),
                ArgvItem::plain(OsStr::new("argv-secret")),
            ]);
        })
        .finish();

    assert!(output.text().as_str().contains("--password"));
    assert!(!output.text().as_str().contains("argv-secret"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Collection admission must stop argv traversal before a later secret item
/// can reach the renderer, and the handle must retain the transaction result.
#[test]
fn argv_handle_stops_at_shared_collection_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_argv([
        ArgvItem::plain(OsStr::new("first")),
        ArgvItem::plain(OsStr::new("later-secret")),
    ]);
    let output = batch.finish();
    let item = output
        .resolve(handle)
        .expect("truncated argv handle publishes");

    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert!(!item.text().as_str().contains("later-secret"));
}

/// Admission must happen before any iterator length is used as an allocation
/// capacity, otherwise an attacker-controlled exact-size iterator can panic
/// before the configured collection limit closes traversal.
#[test]
fn argv_handle_does_not_preallocate_from_unadmitted_iterator_length() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_argv(HugeArgvIterator {
        remaining: usize::MAX,
    });
    let output = batch.finish();
    let item = output.resolve(handle).expect("argv handle publishes");

    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
}
