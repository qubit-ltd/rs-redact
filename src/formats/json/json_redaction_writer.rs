// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable JSON façade over one diagnostic redaction session.

use serde::de::DeserializeSeed;
use serde_json::Deserializer as JsonDeserializer;
use serde_json::from_str;

use super::bounded_json_redaction::redacted_json_text_bounded;
use super::internal::JsonStructureSeed;
use crate::RedactionHandle;
use crate::RedactionSession;
use crate::output::log_escape::escape_log_control_characters;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;

/// Admits every JSON node and collection element through the supplied
/// transaction before a renderer may traverse the parsed value. Returns
/// `false` at the first rejected element; no later sibling is visited.
#[must_use]
pub(crate) fn admit_json_text_structure(session: &mut RedactionSession, text: &str) -> bool {
    admit_json_text_structure_at_depth(session, text, 1)
}

/// Admits JSON text whose root is nested at `root_depth` in another format.
#[must_use]
pub(crate) fn admit_json_text_structure_at_depth(
    session: &mut RedactionSession,
    text: &str,
    root_depth: usize,
) -> bool {
    let mut deserializer = JsonDeserializer::from_str(text);
    let mut rejected = false;
    let admitted = JsonStructureSeed {
        session,
        depth: root_depth,
        collection_item: false,
        rejected: &mut rejected,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end());
    if admitted.is_err() && !rejected {
        return session.admit_format_node(root_depth);
    }
    if admitted.is_err() {
        return false;
    }
    let Ok(value) = from_str(text) else {
        return session.admit_format_node(root_depth);
    };
    session.admit_json_value(&value)
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
    pub(super) session: &'session mut RedactionSession,
}

impl<'session> JsonRedactionWriter<'session> {
    /// Creates a JSON facade borrowing a parent session.
    pub(crate) const fn new(session: &'session mut RedactionSession) -> Self {
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
        if !admit_json_text_structure(self.session, text) {
            self.session.append_rendered_operation(
                OperationSink::truncated("<truncated>", crate::RedactionReason::TraversalLimitReached).finish(),
            );
            return self;
        }
        let result = self.redact_text_direct(text);
        self.session.append_rendered_operation(result);
        self
    }

    /// Redacts JSON text as one individually resolvable transaction item.
    #[must_use]
    pub(crate) fn redact_text(&mut self, text: &str) -> RedactionHandle {
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if self.session.is_output_exhausted() {
                return self.session.stage_exhausted_handle();
            }
            let input_was_empty = text.is_empty();
            let text = self.session.admit_input_prefix(text);
            if text.is_empty() && !input_was_empty {
                return self.session.stage_accounted_text(String::new());
            }
            if !admit_json_text_structure(self.session, text) {
                return self.session.stage_accounted_text("<truncated>");
            }
            let result = self.redact_text_direct(text);
            self.session.stage_rendered_operation(result)
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
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
}

#[cfg(test)]
mod tests {
    use super::redact_json_text_with_limit;
    use crate::RedactionCompletion;
    use crate::RedactionPolicy;
    use crate::Redactor;

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
