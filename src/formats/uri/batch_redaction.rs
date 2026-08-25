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
use crate::runtime::RedactionHandle;
use crate::runtime::runtime_session::RuntimeSession;

/// Redacts one URI as a batch item.
pub(crate) fn redact_uri(session: &mut BatchSession, value: &str) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    let input_was_empty = value.is_empty();
    let value = session.admit_input_prefix(value);
    if value.is_empty() && !input_was_empty {
        return session.stage_accounted_text(String::new());
    }
    if !admit_uri_structure(session, value) {
        return session.stage_accounted_text("<truncated>");
    }
    let result = redact_uri_with_limit(session.policy(), value, session.remaining_output_bytes());
    session.stage_rendered_operation(result)
}
