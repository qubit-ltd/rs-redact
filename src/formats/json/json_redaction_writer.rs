// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable JSON façade over one diagnostic redaction session.

use qubit_budget::json::JsonDecodeSession;
use qubit_json::decode::JsonDecodeErrorKind;
use qubit_json::decode::JsonDecoder;
use serde_json::Value;

use super::JsonAdmissionError;
use super::bounded_json_redaction::BoundedJsonRedaction;
use super::bounded_json_redaction::redacted_json_value_bounded;
use super::internal::JsonStructureSeed;
use crate::output::log_escape::escape_log_control_characters;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Parses `text` at root depth, charging the shared `session` ledger.
///
/// Returns the admitted JSON tree. Returns `JsonAdmissionError::Limit` for a
/// rejected structural or JSON allowance, or `JsonAdmissionError::Invalid` for
/// invalid syntax or unsupported numeric values. The caller admits input bytes.
pub(crate) fn admit_json_text_value(session: &mut dyn RuntimeSession, text: &str) -> Result<Value, JsonAdmissionError> {
    admit_json_text_value_at_depth(session, text, 1)
}

/// Parses `text` with its root at `root_depth`, charging the shared `session`.
///
/// # Parameters
///
/// * `session`: Transaction owning the structural and JSON-value budgets.
/// * `text`: Complete JSON text whose input bytes the caller has already
///   admitted.
/// * `root_depth`: Root-inclusive depth used when admitting this nested
///   document.
///
/// # Returns
///
/// The JSON tree constructed in one admitted decoding pass.
///
/// # Errors
///
/// Returns `JsonAdmissionError::Limit` after structural or JSON-budget
/// rejection, recording JSON-value exhaustion in the session where applicable.
/// Returns `JsonAdmissionError::Invalid` for malformed input or unsupported
/// numbers; error values do not retain source text.
pub(crate) fn admit_json_text_value_at_depth(
    session: &mut dyn RuntimeSession,
    text: &str,
    root_depth: usize,
) -> Result<Value, JsonAdmissionError> {
    #[cfg(test)]
    super::parse_counter::record_json_parse();
    let mut rejected = false;
    let (mut admission, json_budget) = session.split_json_admission();
    let mut decoder = JsonDecoder::new(JsonDecodeSession::borrowing_value(json_budget));
    let admitted = decoder.decode_seed_str(
        JsonStructureSeed {
            admission: &mut admission,
            depth: root_depth,
            collection_item: false,
            rejected: &mut rejected,
        },
        text,
    );
    match admitted {
        Ok(value) => Ok(value),
        Err(_) if rejected => Err(JsonAdmissionError::Limit),
        Err(error) if error.kind() == JsonDecodeErrorKind::Budget => {
            session.record_json_value_limit_reached();
            Err(JsonAdmissionError::Limit)
        }
        Err(_) => Err(JsonAdmissionError::Invalid),
    }
}

/// Copies trusted JSON text under the output allowance supplied by its caller.
///
/// Disabled policies intentionally do not parse or redact their input. This
/// helper performs only log-control escaping and output-bound enforcement.
#[must_use]
pub(crate) fn passthrough_json_text_with_limit(text: &str, max_output_bytes: usize) -> RenderedOperation {
    json_output_from_bounded(BoundedJsonRedaction::Complete(text.to_owned()), max_output_bytes)
}

/// Converts bounded JSON rendering into unpublished adapter state.
#[must_use]
pub(crate) fn json_output_from_bounded(
    bounded: super::bounded_json_redaction::BoundedJsonRedaction,
    max_output_bytes: usize,
) -> RenderedOperation {
    let (rendered, raw_truncated, invalid_json) = bounded.into_parts();
    let output_text = escape_log_control_characters(std::borrow::Cow::Owned(rendered)).into_owned();
    if output_text.len() > max_output_bytes {
        let fallback = "<truncated>";
        let mut output = if fallback.len() <= max_output_bytes {
            OperationSink::truncated(fallback, crate::RedactionReason::OutputLimitReached)
        } else {
            OperationSink::exhausted(String::new())
        };
        if invalid_json {
            output = output.with_reason(crate::RedactionReason::InvalidJson);
        }
        return output.finish();
    }
    if raw_truncated {
        OperationSink::truncated(output_text, crate::RedactionReason::OutputLimitReached).finish()
    } else if invalid_json {
        OperationSink::complete_with_reason(output_text, crate::RedactionReason::InvalidJson).finish()
    } else {
        OperationSink::complete(output_text).finish()
    }
}

/// Feature-gated JSON operations sharing one mutable diagnostic session.
///
/// # Type Parameters
///
/// * `'session` - Borrow of the parent composer's unpublished transaction.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let output = Redactor::standard().text_composer().json(|json| {
///     json.text(r#"{"password":"raw-secret","visible":7}"#);
/// }).finish();
/// assert!(!output.text().as_str().contains("raw-secret"));
/// assert!(output.text().as_str().contains("visible"));
/// ```
pub struct JsonRedactionWriter<'session> {
    /// Text transaction that owns structural accounting and aggregate output.
    pub(super) session: &'session mut TextSession,
}

impl<'session> JsonRedactionWriter<'session> {
    /// Creates a JSON facade borrowing a parent session.
    ///
    /// # Parameters
    ///
    /// * `session` - Parent transaction receiving admitted JSON output.
    ///
    /// # Returns
    ///
    /// A writer borrowing the existing policy and resource ledger.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts JSON text into the parent session's aggregate output.
    ///
    /// # Parameters
    ///
    /// * `text` - One complete JSON document. Enabled redaction parses it once
    ///   under the shared input and traversal limits.
    ///
    /// # Returns
    ///
    /// This writer for further operations; malformed or rejected input uses
    /// safe output and records its cause in the parent summary.
    pub fn text(&mut self, text: &str) -> &mut Self {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        if !self.session.admit_input(text.len()) {
            self.session.append_rendered_operation(
                crate::runtime::OperationSink::truncated("<truncated>", crate::RedactionReason::InputLimitReached)
                    .finish(),
            );
            return self;
        }
        let result = if self.session.policy().is_disabled() {
            self.redact_text_direct(text)
        } else {
            match admit_json_text_value(self.session, text) {
                Ok(value) => self.redact_value_direct(&value),
                Err(JsonAdmissionError::Invalid) => {
                    invalid_json_output(self.session.policy(), self.session.remaining_output_bytes())
                }
                Err(JsonAdmissionError::Limit) => {
                    OperationSink::truncated("<truncated>", crate::RedactionReason::TraversalLimitReached).finish()
                }
            }
        };
        self.session.append_rendered_operation(result);
        self
    }

    /// Redacts a borrowed parsed JSON value into the aggregate transaction.
    ///
    /// # Parameters
    ///
    /// * `value` - Parsed JSON borrowed without cloning or modifying its tree.
    ///
    /// # Returns
    ///
    /// This writer after shared admission and rendering, or after recording a
    /// safe replacement when traversal cannot complete.
    pub fn value(&mut self, value: &Value) -> &mut Self {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        if !self.session.admit_json_value(value) {
            self.session.append_rendered_operation(
                OperationSink::truncated("<truncated>", crate::RedactionReason::TraversalLimitReached).finish(),
            );
            return self;
        }
        let result = self.redact_value_direct(value);
        self.session.append_rendered_operation(result);
        self
    }
}

impl JsonRedactionWriter<'_> {
    /// Escapes previously admitted JSON text for disabled-mode publication.
    ///
    /// The caller performs input admission and checks output closure before
    /// entering this helper. This operation only escapes and bounds the text;
    /// it does not parse or classify JSON.
    #[must_use]
    pub(crate) fn redact_text_direct(&mut self, text: &str) -> RenderedOperation {
        passthrough_json_text_with_limit(text, self.session.remaining_output_bytes())
    }

    /// Redacts a parsed value under the session's remaining output allowance.
    #[must_use]
    pub(crate) fn redact_value_direct(&mut self, value: &Value) -> RenderedOperation {
        redact_json_value_with_limit(self.session.policy(), value, self.session.remaining_output_bytes())
    }
}

/// Redacts a parsed JSON value under a caller-supplied output allowance.
#[must_use]
pub(crate) fn redact_json_value_with_limit(
    policy: &crate::RedactionPolicy,
    value: &Value,
    max_output_bytes: usize,
) -> RenderedOperation {
    json_output_from_bounded(
        redacted_json_value_bounded(value, policy, max_output_bytes),
        max_output_bytes,
    )
}

/// Creates fail-closed output for JSON text that could not be parsed.
pub(crate) fn invalid_json_output(policy: &crate::RedactionPolicy, max_output_bytes: usize) -> RenderedOperation {
    json_output_from_bounded(
        BoundedJsonRedaction::Invalid(policy.masking().mask_opaque(crate::Sensitivity::Secret).to_owned()),
        max_output_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::passthrough_json_text_with_limit;
    use crate::RedactionCompletion;

    /// Verifies the JSON execution helper receives and honors its caller's
    /// final output allowance rather than selecting an independent budget.
    #[test]
    fn test_bounded_json_helper_never_exceeds_the_caller_allowance() {
        let output = passthrough_json_text_with_limit(
            r#"{"description":"this value is deliberately longer than the allowance"}"#,
            16,
        );

        assert_eq!(output.completion(), RedactionCompletion::Truncated);
        assert!(output.reasons().contains(crate::RedactionReason::OutputLimitReached));
        assert!(output.text().len() <= 16);
    }
}
