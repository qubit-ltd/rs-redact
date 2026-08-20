// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared budget and log-boundary helpers for HTTP diagnostics.

use std::borrow::Cow;

use super::HttpPolicyExecutor;
use crate::RedactedText;
use crate::RedactionOutput;
use crate::RedactionReason;
use crate::RedactionSummary;
use crate::formats::http::internal::BoundedLogWriter;
use crate::formats::http::internal::markers;

impl HttpPolicyExecutor<'_> {
    /// Escapes and bounds one diagnostic with an explicit output ceiling.
    #[must_use]
    pub(super) fn finish_diagnostic_with_limit(
        &self,
        text: String,
        max_bytes: usize,
        provenance: Option<RedactionReason>,
    ) -> super::HttpRendered {
        let mut writer = BoundedLogWriter::new(max_bytes, false);
        let _ = writer.write_str(&text);
        let (text, truncated) = writer.finish();
        let summary = if truncated {
            RedactionSummary::truncated(RedactionReason::OutputLimitReached)
        } else {
            RedactionSummary::complete()
        }
        .merge(provenance.map_or_else(RedactionSummary::complete, RedactionSummary::complete_with_reason));
        super::HttpRendered {
            output: RedactionOutput::new(RedactedText::from_escaped(Cow::Owned(text)), summary),
        }
    }

    /// Publishes an already escaped bounded URL rendering with its exact
    /// truncation state.
    #[must_use]
    pub(super) fn finish_rendered_url(&self, text: String, truncated: bool) -> super::HttpRendered {
        let summary = if truncated {
            RedactionSummary::truncated(RedactionReason::OutputLimitReached)
        } else {
            RedactionSummary::complete()
        };
        super::HttpRendered {
            output: RedactionOutput::new(RedactedText::from_escaped(Cow::Owned(text)), summary),
        }
    }
}

/// Bounds an already escaped safe fragment without escaping it a second time.
///
/// Returns empty truncated text when the effective ceiling cannot contain the
/// complete marker; the session result maps that state to `Exhausted`.
pub(in crate::formats::http) fn bound_safe_text(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let marker = markers::TRUNCATED;
    if max_bytes < marker.len() {
        return (String::new(), true);
    }
    let payload_limit = max_bytes.saturating_sub(marker.len());
    // `max_bytes` is an externally configured limit and may be much larger
    // than the rendered prefix, so reserve only as text is actually retained.
    let mut output = String::new();
    for character in text.chars() {
        if output.len().saturating_add(character.len_utf8()) > payload_limit {
            break;
        }
        output.push(character);
    }
    output.push_str(marker);
    (output, true)
}
