// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable JSON façade over one diagnostic redaction session.

use std::borrow::Cow;
use std::io;
use std::io::Write;

use serde_json::Value;
use serde_json::to_writer;

use super::JsonRedactionOutput;
use super::bounded_json_redaction::BoundedJsonRedaction;
use super::bounded_json_redaction::redacted_json_text_bounded;
use super::bounded_json_redaction::redacted_json_value_bounded;
use crate::RedactedText;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::Sensitivity;
use crate::output::MaskedValue;
use crate::output::redaction_output::RedactionOutput;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;

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
    pub fn redact_text_as(&mut self, key: &str, text: &str) -> &mut Self {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = self.redact_text(text);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
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
        input_bytes: usize,
        raw: impl FnOnce(&RedactionPolicy, usize) -> BoundedJsonRedaction,
    ) -> JsonRedactionOutput {
        let policy = self.session.policy();
        let fallback = policy.masking().mask_opaque(Sensitivity::Secret);
        let domain_limit = policy.limits().diagnostic_event().max_output_bytes();
        let before = self.session.remaining_output_bytes();
        match self.session.admit(input_bytes, domain_limit, fallback.len()) {
            RedactionAdmission::Fallback => JsonRedactionOutput::new(
                RedactionOutput::truncated(RedactedText::from_escaped(Cow::Owned(fallback.to_owned())))
                    .unwrap_or_else(RedactionOutput::exhausted),
            ),
            RedactionAdmission::Exhausted => JsonRedactionOutput::new(RedactionOutput::exhausted()),
            RedactionAdmission::Render { max_output_bytes } => {
                let (rendered, raw_truncated) = raw(policy, max_output_bytes).into_parts();
                let escaped = MaskedValue::new(Cow::Owned(rendered)).escape_for_log();
                let (text, mut truncated) = bound_safe_text(escaped.as_str(), max_output_bytes);
                truncated |= raw_truncated;
                let completion = if truncated {
                    if max_output_bytes < before {
                        FragmentCompletion::DomainTruncated
                    } else {
                        FragmentCompletion::SessionTruncated
                    }
                } else {
                    FragmentCompletion::Complete
                };
                self.session.commit_output(text.len(), completion);
                let text = RedactedText::from_escaped(Cow::Owned(text));
                let output = if truncated {
                    RedactionOutput::truncated(text).unwrap_or_else(RedactionOutput::exhausted)
                } else {
                    RedactionOutput::complete(text)
                };
                JsonRedactionOutput::new(output)
            }
        }
    }

    /// Redacts an already parsed JSON value into compact, log-safe JSON text.
    ///
    /// The serialized input size is counted before admission unless the
    /// session is already exhausted. After exhaustion this method returns an
    /// empty [`crate::RedactionCompletion::Exhausted`] result without
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
    pub fn redact_value(&mut self, value: &Value) -> JsonRedactionOutput {
        if self.session.is_exhausted() {
            return JsonRedactionOutput::new(RedactionOutput::exhausted());
        }
        let input_bytes = count_json_bytes(value);
        self.redact_owned(input_bytes, |policy, limit| {
            redacted_json_value_bounded(value, policy, limit)
        })
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
    pub fn redact_text(&mut self, text: &str) -> JsonRedactionOutput {
        self.redact_owned(text.len(), |policy, limit| {
            redacted_json_text_bounded(text, policy, limit)
        })
    }
}

/// Counts the serialized UTF-8 bytes used by a JSON value.
fn count_json_bytes(value: &Value) -> usize {
    /// Sink that counts bytes without retaining the serialized JSON.
    struct Counter(usize);
    impl Write for Counter {
        /// Adds the written byte count to the sink total.
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        /// Flushes the counting sink; no buffered data exists.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    if to_writer(&mut counter, value).is_err() {
        usize::MAX
    } else {
        counter.0
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
