// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable JSON façade over one diagnostic redaction session.

use serde_json::Value;

use super::JsonRedactionOutput;
use super::bounded_json_redaction::BoundedJsonRedaction;
use super::bounded_json_redaction::redacted_json_text_bounded;
use super::bounded_json_redaction::redacted_json_value_bounded;
use crate::RedactionOutput;
use crate::RedactionSession;
use crate::output::MaskedValue;

/// Feature-gated JSON operations sharing one mutable diagnostic session.
pub struct JsonRedactionSession<'session, 'policy> {
    pub(super) session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> JsonRedactionSession<'session, 'policy> {
    /// Creates a JSON facade borrowing a parent session.
    pub(crate) const fn new(session: &'session mut RedactionSession<'policy>) -> Self {
        Self { session }
    }

    /// Redacts JSON text and stages it under `key`.
    pub fn redact_text(&mut self, key: &str, text: &str) -> &mut Self {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = self.redact_text_direct(text);
        let completion = result.completion();
        self.session.stage_text(key, result.into_text(), completion);
        self
    }
}

impl JsonRedactionSession<'_, '_> {
    /// Admits one JSON fragment and maps its bounded rendering into the shared
    /// session completion model.
    ///
    /// Admission happens before `raw` is invoked. Input rejection emits the
    /// configured non-empty opaque fallback when it fits and transitions the
    /// session to truncated; output exhaustion skips `raw`, returns empty
    /// output, and leaves the session closed to later reads. A rendered result
    /// commits exactly its escaped byte length and closes the session when
    /// either JSON processing or final output bounding omitted content.
    #[must_use]
    fn redact_owned(
        &mut self,
        raw: impl FnOnce(&crate::RedactionPolicy, usize) -> BoundedJsonRedaction,
    ) -> JsonRedactionOutput {
        let (rendered, raw_truncated) = raw(self.session.policy(), usize::MAX).into_parts();
        let output_text = MaskedValue::new(std::borrow::Cow::Owned(rendered)).escape_for_log();
        let output = if raw_truncated {
            RedactionOutput::truncated(output_text).unwrap_or_else(RedactionOutput::empty)
        } else {
            RedactionOutput::complete(output_text)
        };
        JsonRedactionOutput::new(output)
    }

    /// Redacts an already parsed JSON value into compact, log-safe JSON text.
    ///
    /// The serialized input size is counted before admission unless the
    /// session is already exhausted. After exhaustion this method returns an
    /// traversing or serializing `value`. Successful admission performs JSON
    /// redaction, commits the bounded output, and may transition the shared
    /// session to truncated when a mask or output budget omits content.
    ///
    /// # Parameters
    ///
    /// * `value` - Materialized JSON value to count, redact, and serialize.
    ///
    /// # Returns
    ///
    /// A compact log-safe result carrying `Complete`, `Truncated`, or
    /// `Exhausted` completion.
    #[must_use]
    pub(crate) fn redact_value_direct(&mut self, value: &Value) -> JsonRedactionOutput {
        self.redact_owned(|policy, limit| redacted_json_value_bounded(value, policy, limit))
    }

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
    pub(crate) fn redact_text_direct(&mut self, text: &str) -> JsonRedactionOutput {
        self.redact_owned(|policy, limit| redacted_json_text_bounded(text, policy, limit))
    }
}

/// Bounds already escaped JSON text without emitting a partial marker.
///
/// # Parameters
///
/// * `text` - Log-safe JSON text to retain when it fits.
/// * `max_bytes` - Effective output ceiling for this session fragment.
///
/// # Returns
///
/// The complete text and `false` when it fits, a marker-terminated prefix and
/// `true` when the complete marker fits, or empty text and `true` when even the
/// marker cannot fit. The empty case is mapped to `Exhausted` by the caller.
fn bound_safe_text(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let marker = "<truncated>";
    if max_bytes < marker.len() {
        return (String::new(), true);
    }
    let payload_limit = max_bytes.saturating_sub(marker.len());
    let mut output = String::with_capacity(max_bytes);
    for character in text.chars() {
        if output.len().saturating_add(character.len_utf8()) > payload_limit {
            break;
        }
        output.push(character);
    }
    output.push_str(marker);
    (output, true)
}
