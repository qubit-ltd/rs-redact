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
    ///
    /// # Parameters
    ///
    /// - `text`: Policy-selected diagnostic text to escape.
    /// - `max_bytes`: Final escaped output-byte ceiling.
    /// - `provenance`: Some additional parser reason, or None when no parser
    ///   reason applies.
    ///
    /// # Returns
    ///
    /// A bounded operation retaining any output-limit and parser reasons.
    #[must_use]
    pub(super) fn finish_diagnostic_with_limit(
        &self,
        text: String,
        max_bytes: usize,
        provenance: Option<RedactionReason>,
    ) -> super::HttpRendered {
        let mut writer = BoundedLogWriter::new(max_bytes, false);
        let _ = writer.write_str(&text);
        let mut operation = writer.finish_operation(RedactionReason::OutputLimitReached);
        if let Some(reason) = provenance {
            operation = operation.with_reason(reason);
        }
        super::HttpRendered::new(operation)
    }

    /// Publishes an already escaped bounded URL rendering with its exact
    /// truncation state.
    ///
    /// # Parameters
    ///
    /// - `text`: Already escaped URL representation.
    /// - `truncated`: Whether URL rendering rejected output bytes.
    ///
    /// # Returns
    ///
    /// A finalized operation with the supplied output-completion state.
    #[must_use]
    #[inline]
    pub(super) fn finish_rendered_url(&self, text: String, truncated: bool) -> super::HttpRendered {
        let operation = if truncated {
            OperationSink::truncated(text, RedactionReason::OutputLimitReached)
        } else {
            OperationSink::complete(text)
        };
        super::HttpRendered::new(operation.finish())
    }
}

/// Bounds an already escaped safe fragment without escaping it a second time.
///
/// Returns empty truncated text when the effective ceiling cannot contain the
/// complete marker; the runtime sink finalizes that state as `Exhausted`.
///
/// # Parameters
///
/// - `text`: Fragment whose log-control escaping is already complete.
/// - `max_bytes`: Effective output-byte ceiling including any truncation
///   marker.
///
/// # Returns
///
/// The bounded fragment and whether it was truncated; an unfit marker yields
/// empty truncated text.
#[must_use]
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
