// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Batch-only URI redaction.

use super::redaction::redact_uri_with_limit;
use super::uri_redaction_writer::admit_uri_structure;
use crate::runtime::BatchSession;
use crate::runtime::OperationSink;
use crate::runtime::RedactionHandle;
use crate::runtime::runtime_session::RuntimeSession;

/// Redacts one URI under the batch session's policy and resource limits.
///
/// The input is admitted before URI structure is charged and rendered output
/// is staged in the session. Rejected input or structure is represented by a
/// safe truncated item.
///
/// # Parameters
///
/// - `session`: Batch transaction supplying the policy, resource budgets, and
///   storage for the staged result.
/// - `value`: URI text to redact.
///
/// # Returns
///
/// A handle identifying the staged item. Retain it to resolve the item's
/// published text after the batch completes.
#[must_use]
pub(crate) fn redact_uri(session: &mut BatchSession, value: &str) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if !session.admit_input(value.len()) {
        return session.stage_rendered_operation(
            OperationSink::truncated("<truncated>", crate::RedactionReason::InputLimitReached).finish(),
        );
    }
    if !admit_uri_structure(session, value) {
        return session.stage_accounted_text("<truncated>");
    }
    let result = redact_uri_with_limit(session.policy(), value, session.remaining_output_bytes());
    session.stage_rendered_operation(result)
}
