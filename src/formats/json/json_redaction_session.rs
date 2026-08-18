// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable JSON façade over one diagnostic redaction session.

use super::JsonRedactionOutput;
use super::bounded_json_redaction::BoundedJsonRedaction;
use super::bounded_json_redaction::redacted_json_text_bounded;
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
