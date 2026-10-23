// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Batch-only JSON redaction.

use serde_json::Value;

use super::JsonAdmissionError;
use super::json_redaction_writer::admit_json_text_value;
use super::json_redaction_writer::invalid_json_output;
use super::json_redaction_writer::passthrough_json_text_with_limit;
use super::json_redaction_writer::redact_json_value_with_limit;
use crate::RedactionReason;
use crate::runtime::BatchSession;
use crate::runtime::OperationSink;
use crate::runtime::RedactionHandle;
use crate::runtime::runtime_session::RuntimeSession;

/// Parses and redacts JSON text while applying the batch session's input and
/// output limits.
///
/// Invalid JSON is rendered according to the active policy. If parsing exceeds
/// an admission limit, the session stages a truncated item instead. The result
/// is staged in the transaction so it can be resolved after the batch ends.
///
/// # Parameters
///
/// - `session`: Batch transaction that supplies the redaction policy and
///   accounts for the staged item.
/// - `text`: JSON document to parse and redact.
///
/// # Returns
///
/// A handle identifying the staged item. Retain it to resolve the item's
/// published text after the batch completes.
#[must_use]
pub(crate) fn redact_text(session: &mut BatchSession, text: &str) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if !session.admit_input(text.len()) {
        return session.stage_rendered_operation(
            OperationSink::truncated("<truncated>", RedactionReason::InputLimitReached).finish(),
        );
    }
    let result = if session.policy().is_disabled() {
        passthrough_json_text_with_limit(text, session.remaining_output_bytes())
    } else {
        match admit_json_text_value(session, text) {
            Ok(value) => redact_json_value_with_limit(session.policy(), &value, session.remaining_output_bytes()),
            Err(JsonAdmissionError::Invalid) => invalid_json_output(session.policy(), session.remaining_output_bytes()),
            Err(JsonAdmissionError::Limit) => {
                return session.stage_accounted_text("<truncated>");
            }
        }
    };
    session.stage_rendered_operation(result)
}

/// Redacts an already parsed JSON value under the batch session's policy and
/// output limit.
///
/// The value is admitted against the session's input and traversal budgets
/// before rendering. The rendered item is staged in the transaction so it can
/// be resolved after the batch ends.
///
/// # Parameters
///
/// - `session`: Batch transaction that supplies the redaction policy and
///   accounts for the staged item.
/// - `value`: Parsed JSON value to redact.
///
/// # Returns
///
/// A handle identifying the staged item. Retain it to resolve the item's
/// published text after the batch completes.
#[must_use]
pub(crate) fn redact_value(session: &mut BatchSession, value: &Value) -> RedactionHandle {
    if session.is_output_exhausted() {
        session.stage_exhausted_handle()
    } else if !session.admit_json_value(value) {
        session.stage_accounted_text("<truncated>")
    } else {
        let result = redact_json_value_with_limit(session.policy(), value, session.remaining_output_bytes());
        session.stage_rendered_operation(result)
    }
}
