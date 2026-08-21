// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared budget and log-boundary helpers for HTTP diagnostics.

use super::HttpPolicyExecutor;
use crate::RedactionReason;
use crate::formats::http::internal::BoundedLogWriter;
use crate::formats::http::internal::markers;
use crate::runtime::OperationSink;

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
        let mut operation = if truncated {
            OperationSink::truncated(text, RedactionReason::OutputLimitReached)
        } else {
            OperationSink::complete(text)
        };
        if let Some(reason) = provenance {
            operation = operation.with_reason(reason);
        }
        super::HttpRendered {
            operation: operation.finish(),
        }
    }

    /// Publishes an already escaped bounded URL rendering with its exact
    /// truncation state.
    #[must_use]
    pub(super) fn finish_rendered_url(&self, text: String, truncated: bool) -> super::HttpRendered {
        let operation = if truncated {
            OperationSink::truncated(text, RedactionReason::OutputLimitReached)
        } else {
            OperationSink::complete(text)
        };
        super::HttpRendered {
            operation: operation.finish(),
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
