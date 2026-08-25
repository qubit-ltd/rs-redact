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
use super::json_redaction_writer::redact_json_text_with_limit;
use super::json_redaction_writer::redact_json_value_with_limit;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;
use crate::runtime::runtime_session::RuntimeSession;

/// Redacts JSON text as a batch item.
pub(crate) fn redact_text(session: &mut BatchSession, text: &str) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    let input_was_empty = text.is_empty();
    let text = session.admit_input_prefix(text);
    if text.is_empty() && !input_was_empty {
        return session.stage_accounted_text(String::new());
    }
    let result = if session.policy().is_disabled() {
        redact_json_text_with_limit(session.policy(), text, session.remaining_output_bytes())
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

/// Redacts a parsed JSON value as a batch item.
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
