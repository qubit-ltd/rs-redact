// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Batch-only argument-vector redaction.

use super::ArgvItem;
use super::redaction::redact_heuristically_with_policy;
use super::redaction::redact_items_with_policy;
use crate::RedactionCompletion;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;
use crate::runtime::runtime_session::RuntimeSession;

/// Redacts explicitly classified arguments as one batch item.
pub(crate) fn redact_items<'items, I>(session: &mut BatchSession, items: I) -> RedactionHandle
where
    I: IntoIterator<Item = ArgvItem<'items>>,
{
    redact(session, items, false)
}

/// Redacts arguments with heuristic classification as one batch item.
pub(crate) fn redact_heuristic_items<'items, I>(session: &mut BatchSession, items: I) -> RedactionHandle
where
    I: IntoIterator<Item = ArgvItem<'items>>,
{
    redact(session, items, true)
}

/// Runs one argv renderer after bounded admission.
fn redact<'items, I>(session: &mut BatchSession, items: I, heuristic: bool) -> RedactionHandle
where
    I: IntoIterator<Item = ArgvItem<'items>>,
{
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    let Some(items) = collect_admitted_items(session, items) else {
        return session.stage_accounted_text(String::new());
    };
    let result = if heuristic {
        redact_heuristically_with_policy(session.policy(), items, session.remaining_output_bytes())
    } else {
        redact_items_with_policy(session.policy(), items, session.remaining_output_bytes())
    };
    if result.text().is_empty() && result.completion() == RedactionCompletion::Truncated {
        session.stage_exhausted_handle()
    } else {
        session.stage_rendered_operation(result)
    }
}

/// Collects arguments only while shared admission succeeds.
fn collect_admitted_items<'items, I>(session: &mut BatchSession, items: I) -> Option<Vec<ArgvItem<'items>>>
where
    I: IntoIterator<Item = ArgvItem<'items>>,
{
    if !session.admit_format_node(1) {
        return None;
    }
    let mut iterator = items.into_iter();
    let mut admitted = Vec::new();
    loop {
        if iterator.size_hint().1 == Some(0) {
            break;
        }
        if !session.preflight_format_item(2) {
            return None;
        }
        let Some(item) = iterator.next() else {
            break;
        };
        if !session.admit_format_collection_item() || !session.admit_format_node(2) {
            return None;
        }
        if !session.admit_input(item.value().as_encoded_bytes().len()) {
            return None;
        }
        admitted.push(item);
    }
    Some(admitted)
}
