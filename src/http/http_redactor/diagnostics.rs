// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared budget and log-boundary helpers for HTTP diagnostics.

use std::borrow::Cow;

use super::HttpRedactor;
use crate::LogSafeText;
use crate::http::internal::BoundedLogWriter;
use crate::http::internal::markers;

impl HttpRedactor {
    /// Reports whether a diagnostic input exceeds the hard input limit.
    pub(super) fn diagnostic_input_exceeded(&self, input_bytes: usize) -> bool {
        input_bytes > self.policy().limits().diagnostic_event().max_input_bytes()
    }

    /// Returns the fixed log-safe diagnostic-limit marker.
    pub(super) fn diagnostic_limit_exceeded() -> LogSafeText<'static> {
        LogSafeText::from_escaped(Cow::Borrowed(markers::DIAGNOSTIC_LIMIT_EXCEEDED))
    }

    /// Escapes and bounds one redacted HTTP diagnostic.
    pub(super) fn finish_diagnostic(&self, text: String) -> LogSafeText<'static> {
        self.finish_diagnostic_with_limit(
            text,
            self.policy().limits().diagnostic_event().max_output_bytes(),
        )
    }

    /// Escapes and bounds one diagnostic with an explicit output ceiling.
    pub(super) fn finish_diagnostic_with_limit(
        &self,
        text: String,
        max_bytes: usize,
    ) -> LogSafeText<'static> {
        let mut writer = BoundedLogWriter::new(max_bytes, false);
        let _ = writer.write_str(&text);
        let (text, _) = writer.finish();
        LogSafeText::from_escaped(Cow::Owned(text))
    }
}

/// Bounds an already escaped safe fragment without escaping it a second time.
pub(in crate::http) fn bound_safe_text(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let marker = markers::TRUNCATED;
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
