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
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;
use crate::runtime::collect_flat_format_items;
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
    let Some(items) = collect_flat_format_items(session, items, |item| item.value().as_encoded_bytes().len()) else {
        return session.stage_accounted_text(String::new());
    };
    let result = if heuristic {
        redact_heuristically_with_policy(session.policy(), items, session.remaining_output_bytes())
    } else {
        redact_items_with_policy(session.policy(), items, session.remaining_output_bytes())
    };
    session.stage_rendered_operation(result)
}
