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
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;
use crate::runtime::admit_flat_format_item;
use crate::runtime::collect_flat_format_items;
use crate::runtime::runtime_session::RuntimeSession;

/// Redacts one environment pair as a batch item.
pub(crate) fn redact_pair(session: &mut BatchSession, name: &str, value: &str) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if !admit_flat_format_item(session, name.len().saturating_add(value.len())) {
        return session.stage_accounted_text(String::new());
    }
    let result = redact_pair_with_policy(session.policy(), name, value, session.remaining_output_bytes());
    session.stage_rendered_operation(result)
}

/// Redacts environment pairs as a batch item.
pub(crate) fn redact_os_pairs<'items, I>(session: &mut BatchSession, pairs: I) -> RedactionHandle
where
    I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
{
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    let Some(pairs) = collect_flat_format_items(session, pairs, |(name, value)| {
        name.as_encoded_bytes()
            .len()
            .saturating_add(value.as_encoded_bytes().len())
    }) else {
        return session.stage_accounted_text(String::new());
    };
    let result = redact_os_pairs_with_policy(session.policy(), pairs, session.remaining_output_bytes());
    session.stage_rendered_operation(result)
}
