// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable JSON façade over one diagnostic redaction session.

use qubit_json::decode::JsonDecoder;
use serde_json::Value;

use super::JsonAdmissionError;
use super::bounded_json_redaction::BoundedJsonRedaction;
use super::bounded_json_redaction::redacted_json_text_bounded;
use super::bounded_json_redaction::redacted_json_value_bounded;
use super::internal::JsonStructureSeed;
use crate::output::log_escape::escape_log_control_characters;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Admits JSON text whose root is nested at `root_depth` in another format.
#[must_use]
#[cfg(feature = "http")]
pub(crate) fn admit_json_text_structure_at_depth(
    session: &mut dyn RuntimeSession,
    text: &str,
    root_depth: usize,
) -> bool {
    admit_json_text_value_at_depth(session, text, root_depth).is_ok()
}

/// Parses and admits one complete JSON text value at the root depth.
pub(crate) fn admit_json_text_value(session: &mut dyn RuntimeSession, text: &str) -> Result<Value, JsonAdmissionError> {
    admit_json_text_value_at_depth(session, text, 1)
}

/// Parses and admits JSON text whose root appears at the supplied depth.
pub(crate) fn admit_json_text_value_at_depth(
    session: &mut dyn RuntimeSession,
    text: &str,
    root_depth: usize,
) -> Result<Value, JsonAdmissionError> {
    #[cfg(test)]
    super::parse_counter::record_json_parse();
    let mut rejected = false;
    let admitted = JsonDecoder::unlimited().decode_seed_str(
        JsonStructureSeed {
            session,
            depth: root_depth,
            collection_item: false,
            rejected: &mut rejected,
        },
        text,
    );
    match admitted {
        Ok(value) if session.admit_json_value(&value) => Ok(value),
        Ok(_) => Err(JsonAdmissionError::Limit),
        Err(_) if rejected => Err(JsonAdmissionError::Limit),
        Err(_) => Err(JsonAdmissionError::Invalid),
    }
}

/// Redacts JSON text under the output allowance supplied by its caller.
///
/// This helper owns no session state. The caller supplies the remaining
/// transaction allowance, so JSON parsing cannot create a second output
/// budget. The returned text is already escaped and never exceeds that
/// allowance.
#[must_use]
pub(crate) fn redact_json_text_with_limit(
    policy: &crate::RedactionPolicy,
    text: &str,
    max_output_bytes: usize,
) -> RenderedOperation {
    json_output_from_bounded(
        redacted_json_text_bounded(text, policy, max_output_bytes),
        max_output_bytes,
    )
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
            OperationSink::exhausted(String::new(), crate::RedactionReason::OutputLimitReached)
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
pub struct JsonRedactionWriter<'session> {
    /// Text transaction that owns structural accounting and aggregate output.
    pub(super) session: &'session mut TextSession,
}

impl<'session> JsonRedactionWriter<'session> {
    /// Creates a JSON facade borrowing a parent session.
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts JSON text into the parent session's aggregate output.
    pub fn text(&mut self, text: &str) -> &mut Self {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        let input_was_empty = text.is_empty();
        let text = self.session.admit_input_prefix(text);
        if text.is_empty() && !input_was_empty {
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
    /// Parses and redacts JSON text into compact, log-safe JSON text.
    ///
    /// The text byte length is offered to the shared budget before parsing or
    /// redaction. Rejected input therefore cannot be parsed: the method emits
    /// a safe fallback when one fits, or empty exhausted output otherwise.
    /// Once output exhaustion closes the session, later calls stop before
    /// invoking the parser. Successful admission commits only the bounded,
    /// escaped output and reports any budget-caused omission as truncated.
    ///
    /// # Parameters
    ///
    /// * `text` - JSON source whose byte length is charged on admission.
    ///
    /// # Returns
    ///
    /// A compact log-safe result carrying `Complete`, `Truncated`, or
    /// `Exhausted` completion.
    #[must_use]
    pub(crate) fn redact_text_direct(&mut self, text: &str) -> RenderedOperation {
        redact_json_text_with_limit(self.session.policy(), text, self.session.remaining_output_bytes())
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
    use super::super::parse_counter::json_parse_count;
    use super::super::parse_counter::reset_json_parse_count;
    use super::redact_json_text_with_limit;
    use crate::RedactionCompletion;
    use crate::RedactionPolicy;
    use crate::Redactor;

    #[test]
    fn enabled_json_text_is_parsed_exactly_once() {
        reset_json_parse_count();

        let output = Redactor::standard().redact_json(r#"{"token":"raw-secret"}"#);

        assert_eq!(json_parse_count(), 1);
        assert!(!output.text().as_str().contains("raw-secret"));
    }

    #[test]
    fn admitted_json_tree_covers_every_scalar_parser_representation() {
        for text in [
            "null",
            "true",
            "-1",
            "1",
            "1.5",
            r#""visible""#,
            r#"[null,true,-1,1,1.5,"visible"]"#,
        ] {
            let output = Redactor::standard().redact_json(text);

            assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
        }
    }

    /// Verifies the JSON execution helper receives and honors its caller's
    /// final output allowance rather than selecting an independent budget.
    #[test]
    fn bounded_json_helper_never_exceeds_the_caller_allowance() {
        let output = redact_json_text_with_limit(
            &RedactionPolicy::standard(),
            r#"{"description":"this value is deliberately longer than the allowance"}"#,
            16,
        );

        assert_eq!(output.completion(), RedactionCompletion::Truncated);
        assert!(output.reasons().contains(crate::RedactionReason::OutputLimitReached));
        assert!(output.text().len() <= 16);
    }

    /// Verifies a JSON adapter sees bytes already committed by the enclosing
    /// transaction when choosing its rendering limit.
    #[test]
    fn json_session_uses_the_transaction_remaining_output_allowance() {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                let _ = limits.max_output_bytes(20);
            })
            .expect("the test limit draft should build")
            .build()
            .expect("the test policy should build");
        let output = Redactor::new(policy)
            .text_composer()
            .literal("prefix")
            .json(|json| {
                json.text(r#"{"description":"this value is deliberately longer than the allowance"}"#);
            })
            .finish();

        assert_eq!(output.text().as_str(), "prefix<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert_eq!(output.summary().usage().output_bytes(), 17);
    }
}
