// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable JSON façade over one diagnostic redaction session.

use std::io::Write;

use qubit_budget::json::JsonDecodeSession;
use qubit_json::decode::JsonDecodeErrorKind;
use qubit_json::decode::JsonDecoder;
use serde_json::Value;

use super::JsonAdmissionError;
use super::bounded_json_redaction::BoundedJsonRedaction;
use super::bounded_json_redaction::redacted_json_value_bounded;
use super::internal::JsonStructureSeed;
use crate::output::log_escape::encode_log_safe_character;
use crate::output::log_escape::escape_log_control_characters;
use crate::runtime::OperationByteSink;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Parses `text` at root depth, charging the shared `session` ledger.
///
/// The caller admits input bytes before calling this helper.
///
/// # Parameters
///
/// * `session`: Transaction that owns the structural and JSON-value budgets.
/// * `text`: Complete JSON document whose input bytes have already been
///   admitted.
///
/// # Returns
///
/// The admitted JSON tree.
///
/// # Errors
///
/// Returns `JsonAdmissionError::Limit` when structural or JSON-value admission
/// is rejected, or `JsonAdmissionError::Invalid` for malformed syntax or
/// unsupported numbers, or duplicate object keys. Error values do not retain
/// source text.
pub(crate) fn admit_json_text_value(session: &mut dyn RuntimeSession, text: &str) -> Result<Value, JsonAdmissionError> {
    let root_depth = session.json_root_depth();
    admit_json_text_value_at_depth(session, text, root_depth)
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
/// The JSON tree constructed under lexical JSON limits, then admitted through
/// the shared structural ledger using native numeric events.
///
/// # Errors
///
/// Returns `JsonAdmissionError::Limit` after structural or JSON-budget
/// rejection, recording JSON-value exhaustion in the session where applicable.
/// Returns `JsonAdmissionError::Invalid` for malformed input, unsupported
/// numbers, or duplicate keys; error values
/// do not retain source text.
pub(crate) fn admit_json_text_value_at_depth(
    session: &mut dyn RuntimeSession,
    text: &str,
    root_depth: usize,
) -> Result<Value, JsonAdmissionError> {
    #[cfg(test)]
    super::parse_counter::record_json_parse();
    let mut rejected = false;
    let (mut admission, json_budget) = session.split_json_admission();
    let preflight = admission.json_preflight(root_depth);
    if let Err(error) = preflight.validate(text) {
        admission.reject_preflight(error);
        return match error {
            crate::runtime::JsonStructurePreflightError::Invalid => Err(JsonAdmissionError::Invalid),
            crate::runtime::JsonStructurePreflightError::DepthLimit
            | crate::runtime::JsonStructurePreflightError::TraversalLimit => Err(JsonAdmissionError::Limit),
        };
    }
    #[cfg(test)]
    super::parse_counter::record_json_materialization();
    let mut decoder = JsonDecoder::new(JsonDecodeSession::borrowing_value(json_budget));
    let admitted = decoder.decode_unique_seed_utf8(
        JsonStructureSeed {
            admission: &mut admission,
            depth: root_depth,
            collection_item: false,
            rejected: &mut rejected,
        },
        text.as_bytes(),
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
///
/// # Parameters
///
/// * `text`: Trusted JSON text to pass through after escaping log controls.
/// * `max_output_bytes`: Maximum number of bytes allowed in the rendered text.
///
/// # Returns
///
/// A bounded, unpublished rendering with truncation provenance when needed.
pub(crate) fn passthrough_json_text_with_limit(text: &str, max_output_bytes: usize) -> RenderedOperation {
    let mut writer = OperationByteSink::new(max_output_bytes);
    let mut encoded = [0_u8; 12];
    for character in text.chars() {
        let piece = encode_log_safe_character(character, &mut encoded)
            .expect("log-safe character encoding must fit its fixed buffer");
        if writer.write_all(piece.as_bytes()).is_err() {
            return if "<truncated>".len() <= max_output_bytes {
                OperationSink::truncated("<truncated>", crate::RedactionReason::OutputLimitReached).finish()
            } else {
                OperationSink::exhausted(String::new())
                    .with_reason(crate::RedactionReason::OutputLimitReached)
                    .finish()
            };
        }
    }
    OperationSink::complete(
        writer
            .into_string()
            .expect("log-safe JSON text encoding must produce valid UTF-8"),
    )
    .finish()
}

/// Converts bounded JSON rendering into unpublished adapter state.
///
/// # Parameters
///
/// * `bounded`: Escaped or redacted rendering and its completion metadata.
/// * `max_output_bytes`: Maximum number of bytes allowed in the final text.
///
/// # Returns
///
/// An unpublished operation that retains completion and degradation reasons.
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
                Err(JsonAdmissionError::Limit) => OperationSink::complete("<truncated>").finish(),
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
            self.session
                .append_rendered_operation(OperationSink::complete("<truncated>").finish());
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
    ///
    /// # Parameters
    ///
    /// * `text`: Previously admitted JSON text to publish in disabled mode.
    ///
    /// # Returns
    ///
    /// An unpublished, escaped operation bounded by the session's remaining
    /// output allowance.
    pub(crate) fn redact_text_direct(&mut self, text: &str) -> RenderedOperation {
        passthrough_json_text_with_limit(text, self.session.remaining_output_bytes())
    }

    /// Redacts a parsed value under the session's remaining output allowance.
    ///
    /// # Parameters
    ///
    /// * `value`: Parsed JSON value to redact without modifying its tree.
    ///
    /// # Returns
    ///
    /// An unpublished operation containing the bounded redacted rendering.
    pub(crate) fn redact_value_direct(&mut self, value: &Value) -> RenderedOperation {
        redact_json_value_with_limit(self.session.policy(), value, self.session.remaining_output_bytes())
    }
}

/// Redacts a parsed JSON value under a caller-supplied output allowance.
///
/// # Parameters
///
/// * `policy`: Redaction policy applied to sensitive JSON values.
/// * `value`: Parsed JSON value to render without modifying its tree.
/// * `max_output_bytes`: Maximum number of bytes allowed in the final text.
///
/// # Returns
///
/// An unpublished operation containing bounded redacted JSON.
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
///
/// # Parameters
///
/// * `policy`: Policy supplying the opaque secret mask.
/// * `max_output_bytes`: Maximum number of bytes allowed in the final text.
///
/// # Returns
///
/// An unpublished operation containing the bounded opaque mask and invalid-JSON
/// provenance.
pub(crate) fn invalid_json_output(policy: &crate::RedactionPolicy, max_output_bytes: usize) -> RenderedOperation {
    let rejected = || {
        let sink = if "<truncated>".len() <= max_output_bytes {
            OperationSink::truncated("<truncated>", crate::RedactionReason::OutputLimitReached)
        } else {
            OperationSink::exhausted(String::new()).with_reason(crate::RedactionReason::OutputLimitReached)
        };
        sink.with_reason(crate::RedactionReason::InvalidJson).finish()
    };
    let mut writer = OperationByteSink::new(max_output_bytes);
    let mut buffer = [0_u8; 12];
    for character in policy.masking().mask_opaque(crate::Sensitivity::Secret).chars() {
        let Ok(piece) = encode_log_safe_character(character, &mut buffer) else {
            return rejected();
        };
        if writer.write_all(piece.as_bytes()).is_err() {
            return rejected();
        }
    }
    match writer.into_string() {
        Some(text) => json_output_from_bounded(BoundedJsonRedaction::Invalid(text), max_output_bytes),
        None => rejected(),
    }
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
