// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Batch-only environment redaction.

use std::ffi::OsStr;

use super::operation;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;

/// Redacts one UTF-8 environment pair as an individually resolvable batch item.
///
/// The name is used for policy classification, and both strings are admitted
/// against the session's input and output budgets before the rendered result is
/// staged.
///
/// # Parameters
///
/// - `session`: Batch transaction that supplies the policy and accounts for the
///   staged item.
/// - `name`: Environment variable name used for classification.
/// - `value`: Borrowed UTF-8 environment value.
///
/// # Returns
///
/// A handle identifying the staged item. The caller must retain it to resolve
/// the item's published text after the batch finishes.
#[must_use]
pub(crate) fn redact_pair(session: &mut BatchSession, name: &str, value: &str) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    match operation::redact_pair(session, name, value) {
        Some(result) => session.stage_rendered_operation(result),
        None => session.stage_accounted_text(String::new()),
    }
}

/// Redacts borrowed OS-string environment pairs as one batch item.
///
/// Pairs are consumed in iterator order and admitted under the session's
/// shared budgets. Non-UTF-8 values are handled by the environment renderer
/// according to the active policy.
///
/// # Type Parameters
///
/// - `'items`: Borrow lifetime shared by each environment name and value.
/// - `I`: Iterator source yielding borrowed OS-string pairs.
///
/// # Parameters
///
/// - `session`: Batch transaction that supplies the policy and accounts for the
///   staged item.
/// - `pairs`: Finite sequence of borrowed environment names and values.
///
/// # Returns
///
/// A handle identifying the staged combined item. The caller must retain it
/// to resolve the item's published text after the batch finishes.
#[must_use]
pub(crate) fn redact_os_pairs<'items, I>(session: &mut BatchSession, pairs: I) -> RedactionHandle
where
    I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
{
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    match operation::redact_os_pairs(session, pairs) {
        Some(result) => session.stage_rendered_operation(result),
        None => session.stage_accounted_text(String::new()),
    }
}
