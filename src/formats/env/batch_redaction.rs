// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Batch-only environment redaction.

use std::ffi::OsStr;

use super::admission::{admit_environment_name, collect_environment_pairs};
use super::redaction::redact_os_pairs_with_policy;
use super::redaction::redact_pair_with_policy;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;
use crate::runtime::runtime_session::RuntimeSession;

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
    if !session.admit_format_node(1)
        || !session.admit_format_collection_item()
        || !session.admit_format_node(2)
        || !admit_environment_name(session, OsStr::new(name))
        || !session.admit_input(name.len().saturating_add(value.len()))
    {
        return session.stage_accounted_text(String::new());
    }
    let result = redact_pair_with_policy(
        session.policy(),
        name,
        value,
        session.remaining_output_bytes(),
    );
    session.stage_rendered_operation(result)
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
    let Some(pairs) = collect_environment_pairs(session, pairs) else {
        return session.stage_accounted_text(String::new());
    };
    let result =
        redact_os_pairs_with_policy(session.policy(), pairs, session.remaining_output_bytes());
    session.stage_rendered_operation(result)
}
