// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Batch-only argument-vector redaction.

use super::ArgvItem;
use super::operation::redact_items as redact_argv_items;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;

/// Redacts explicitly classified arguments as one batch item.
pub(crate) fn redact_items<'items, I>(session: &mut BatchSession, items: I) -> RedactionHandle
where
    I: IntoIterator<Item = ArgvItem<'items>>,
{
    redact(session, items, false)
}

/// Redacts arguments with heuristic classification as one batch item.
pub(crate) fn redact_heuristic_items<'items, I>(
    session: &mut BatchSession,
    items: I,
) -> RedactionHandle
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
    match redact_argv_items(session, items, heuristic) {
        Some(operation) => session.stage_rendered_operation(operation),
        None => session.stage_accounted_text(String::new()),
    }
}
