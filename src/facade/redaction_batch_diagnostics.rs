// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fail-closed presentation of independently resolvable batch results.

use std::borrow::Cow;

use super::RedactedText;
use super::RedactionBatchHandle;
use super::RedactionBatchOutput;
use super::RedactionSummary;
use crate::output::log_escape::escape_log_control_characters;

/// Presents batch items for diagnostics without exposing resolution errors.
///
/// A complete item retains its redacted text. An incomplete item, a missing
/// item, or a handle created by another batch resolves to one caller-selected
/// marker. This fail-closed behavior is intended for `Debug`, `Display`, logs,
/// and other presentation paths that cannot recover from individual handle
/// failures. The public batch contract deliberately maps every unresolved or
/// incomplete item to the same safe marker.
///
/// The marker is escaped once when this object is created, so repeated
/// resolution neither allocates nor permits control characters to forge log
/// structure.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let mut batch = Redactor::strict().batch();
/// let handle = batch.redact_field("password", "raw-secret");
/// let diagnostics = batch.finish_for_diagnostics("<redaction incomplete>");
/// assert_eq!(diagnostics.text(handle).as_str(), "<redacted>");
/// ```
pub struct RedactionBatchDiagnostics {
    /// Strict publication that owns the batch identity, items, and summary.
    output: RedactionBatchOutput,
    /// Escaped fallback used for incomplete or unresolvable items.
    marker: RedactedText,
}

impl RedactionBatchDiagnostics {
    /// Creates a diagnostic view over one completed batch publication.
    ///
    /// `marker` is escaped immediately and reused for every fail-closed
    /// resolution.
    #[must_use]
    pub(crate) fn new(output: RedactionBatchOutput, marker: &str) -> Self {
        let marker = escape_log_control_characters(Cow::Borrowed(marker));
        Self {
            output,
            marker: RedactedText::from_escaped(marker.into_owned()),
        }
    }

    /// Resolves an item to complete redacted text or the shared marker.
    ///
    /// The marker is returned when `handle` belongs to another batch, names a
    /// missing item, or identifies an item whose completion is `Truncated` or
    /// `Exhausted`. No allocation occurs during resolution.
    #[must_use]
    #[inline]
    pub fn text(&self, handle: RedactionBatchHandle) -> &RedactedText {
        self.output
            .resolve(handle)
            .ok()
            .and_then(|output| output.complete_text().ok())
            .unwrap_or(&self.marker)
    }

    /// Returns the aggregate accounting summary for the underlying batch.
    #[must_use]
    #[inline(always)]
    pub const fn summary(&self) -> &RedactionSummary {
        self.output.summary()
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::RedactionBatchHandle;
    use crate::Redactor;

    /// A missing item from the same batch reuses the escaped diagnostic marker.
    #[test]
    fn test_text_reuses_escaped_marker_for_missing_same_batch_item() {
        let mut batch = Redactor::standard().batch();
        let valid = batch.redact_field("name", "Ada");
        let missing = RedactionBatchHandle {
            batch_id: valid.batch_id,
            item_index: usize::MAX,
        };
        let diagnostics = batch.finish_for_diagnostics("<redaction\nincomplete>");

        let first = diagnostics.text(missing);
        let second = diagnostics.text(missing);

        assert_eq!(first.as_str(), "<redaction\\nincomplete>");
        assert!(ptr::eq(first, second));
    }
}
