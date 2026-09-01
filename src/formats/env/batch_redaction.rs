// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Batch-only environment redaction.

use std::ffi::OsStr;

use super::redaction::redact_os_pairs_with_policy;
use super::redaction::redact_pair_with_policy;
use crate::RedactionCompletion;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;
use crate::runtime::runtime_session::RuntimeSession;

/// Redacts one environment pair as a batch item.
pub(crate) fn redact_pair(session: &mut BatchSession, name: &str, value: &str) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if !session.admit_format_node(1)
        || !session.admit_format_collection_item()
        || !session.admit_format_node(2)
        || !session.admit_input(name.len().saturating_add(value.len()))
    {
        return session.stage_accounted_text(String::new());
    }
    let result = redact_pair_with_policy(session.policy(), name, value, session.remaining_output_bytes());
    stage(session, result)
}

/// Redacts environment pairs as a batch item.
pub(crate) fn redact_os_pairs<'items, I>(session: &mut BatchSession, pairs: I) -> RedactionHandle
where
    I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
{
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    let Some(pairs) = collect_admitted_pairs(session, pairs) else {
        return session.stage_accounted_text(String::new());
    };
    let result = redact_os_pairs_with_policy(session.policy(), pairs, session.remaining_output_bytes());
    stage(session, result)
}

/// Stages one environment operation, preserving truncation semantics.
fn stage(session: &mut BatchSession, result: crate::runtime::RenderedOperation) -> RedactionHandle {
    if result.text().is_empty() && result.completion() == RedactionCompletion::Truncated {
        session.stage_exhausted_handle()
    } else {
        session.stage_rendered_operation(result)
    }
}

/// Collects pairs only while shared admission succeeds.
fn collect_admitted_pairs<'items, I>(
    session: &mut BatchSession,
    pairs: I,
) -> Option<Vec<(&'items OsStr, &'items OsStr)>>
where
    I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
{
    if !session.admit_format_node(1) {
        return None;
    }
    let mut iterator = pairs.into_iter();
    let mut admitted = Vec::new();
    loop {
        if iterator.size_hint().1 == Some(0) {
            break;
        }
        if !session.preflight_format_item(2) {
            return None;
        }
        let Some((name, value)) = iterator.next() else {
            break;
        };
        if !session.admit_format_collection_item() || !session.admit_format_node(2) {
            return None;
        }
        if !session.admit_input(
            name.as_encoded_bytes()
                .len()
                .saturating_add(value.as_encoded_bytes().len()),
        ) {
            return None;
        }
        admitted.push((name, value));
    }
    Some(admitted)
}
