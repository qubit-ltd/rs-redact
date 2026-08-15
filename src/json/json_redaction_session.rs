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

use super::redact_json_text_in_place::redacted_json_text_bounded;
use super::redact_json_text_in_place::redacted_json_value_bounded;
use crate::LogSafeText;
use crate::RedactedText;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::Sensitivity;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;

/// Feature-gated JSON operations sharing one mutable diagnostic session.
#[must_use = "use the session-bounded JSON result"]
pub struct JsonRedactionSession<'session, 'policy> {
    pub(super) session: &'session mut RedactionSession<'policy>,
}

impl JsonRedactionSession<'_, '_> {
    fn redact_owned(
        &mut self,
        input_bytes: usize,
        raw: impl FnOnce(&RedactionPolicy, usize) -> String,
    ) -> LogSafeText<'static> {
        let policy = self.session.policy();
        let fallback = policy.masking().mask_opaque(Sensitivity::Secret);
        let domain_limit =
            policy.limits().diagnostic_event().max_output_bytes();
        let before = self.session.remaining_output_bytes();
        match self
            .session
            .admit(input_bytes, domain_limit, fallback.len())
        {
            RedactionAdmission::Fallback => {
                LogSafeText::from_escaped(Cow::Owned(fallback.to_owned()))
            }
            RedactionAdmission::Exhausted => {
                LogSafeText::from_escaped(Cow::Borrowed(""))
            }
            RedactionAdmission::Render { max_output_bytes } => {
                let rendered = raw(policy, max_output_bytes);
                let escaped =
                    RedactedText::new(Cow::Owned(rendered)).escape_for_log();
                let (text, mut truncated) =
                    bound_safe_text(escaped.as_str(), max_output_bytes);
                if escaped.as_str() == "<truncated>" {
                    truncated = true;
                }
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
                LogSafeText::from_escaped(Cow::Owned(text))
            }
        }
    }

    /// Redacts an already parsed JSON value into compact, log-safe JSON text.
    pub fn redact_value(&mut self, value: &Value) -> LogSafeText<'static> {
        if self.session.is_exhausted() {
            return LogSafeText::from_escaped(Cow::Borrowed(""));
        }
        let input_bytes = count_json_bytes(value);
        self.redact_owned(input_bytes, |policy, limit| {
            redacted_json_value_bounded(value, policy, limit)
        })
    }

    /// Parses and redacts JSON text into compact, log-safe JSON text.
    pub fn redact_text(&mut self, text: &str) -> LogSafeText<'static> {
        self.redact_owned(text.len(), |policy, limit| {
            redacted_json_text_bounded(text, policy, limit)
        })
    }
}

fn count_json_bytes(value: &Value) -> usize {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
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

fn bound_safe_text(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let marker = "<truncated>";
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

impl<'policy> RedactionSession<'policy> {
    /// Creates the JSON façade borrowing this session's policy and budget.
    #[inline]
    pub fn json<'session>(
        &'session mut self,
    ) -> JsonRedactionSession<'session, 'policy> {
        JsonRedactionSession { session: self }
    }
}
