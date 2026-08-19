// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Atomically published output from one redaction session.

use crate::RedactedText;
use crate::RedactionHandle;
use crate::RedactionHandleError;
use crate::RedactionOutput;
use crate::RedactionSummary;

/// Final output published after a session commits successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionSessionOutput {
    transaction_id: u64,
    output: RedactionOutput,
    items: Vec<RedactionOutput>,
}

impl RedactionSessionOutput {
    /// Creates a published session output.
    pub(crate) fn new(
        transaction_id: u64,
        text: RedactedText,
        items: Vec<RedactionOutput>,
        summary: RedactionSummary,
    ) -> Self {
        Self {
            transaction_id,
            output: RedactionOutput::new(text, summary),
            items,
        }
    }

    /// Returns the composed safe text.
    #[must_use]
    pub const fn text(&self) -> &RedactedText {
        self.output.text()
    }

    /// Returns the aggregate summary.
    #[must_use]
    pub const fn summary(&self) -> &RedactionSummary {
        self.output.summary()
    }

    /// Consumes this published transaction and returns the item selected by
    /// `handle` without cloning its final redacted text.
    ///
    /// Returns [`RedactionHandleError::DifferentTransaction`] when `handle`
    /// originated from another transaction and
    /// [`RedactionHandleError::MissingItem`] when its item index is invalid.
    pub fn into_resolved(self, handle: RedactionHandle) -> Result<RedactionOutput, RedactionHandleError> {
        if handle.transaction_id != self.transaction_id {
            return Err(RedactionHandleError::DifferentTransaction);
        }
        self.items
            .into_iter()
            .nth(handle.item_index)
            .ok_or(RedactionHandleError::MissingItem)
    }

    /// Resolves one item handle published by this transaction.
    ///
    /// Returns [`RedactionHandleError::DifferentTransaction`] when `handle`
    /// originated from another transaction and
    /// [`RedactionHandleError::MissingItem`] when its item index is invalid.
    pub fn resolve(&self, handle: RedactionHandle) -> Result<&RedactionOutput, RedactionHandleError> {
        if handle.transaction_id != self.transaction_id {
            return Err(RedactionHandleError::DifferentTransaction);
        }
        self.items
            .get(handle.item_index)
            .ok_or(RedactionHandleError::MissingItem)
    }
}

#[cfg(test)]
mod tests {
    use super::RedactionHandle;
    use super::RedactionHandleError;
    use super::RedactionOutput;
    use super::RedactionSessionOutput;
    use crate::RedactedText;
    use crate::RedactionSummary;

    /// An invalid same-transaction index is reported distinctly from an
    /// ordinary cross-transaction handle mismatch.
    #[test]
    fn resolve_reports_missing_same_transaction_item() {
        let output = RedactionSessionOutput::new(
            7,
            RedactedText::from_escaped("aggregate"),
            Vec::new(),
            RedactionSummary::complete(),
        );

        assert_eq!(output.text().as_str(), "aggregate");
        assert_eq!(*output.summary(), RedactionSummary::complete());
        assert_eq!(
            output.resolve(RedactionHandle::new(7, 0)),
            Err(RedactionHandleError::MissingItem)
        );
    }

    /// Valid items resolve by their insertion index without exposing those
    /// indices through the public opaque handle type.
    #[test]
    fn resolve_returns_the_published_item_for_its_transaction() {
        let item = RedactionOutput::new(RedactedText::from_escaped("item"), RedactionSummary::complete());
        let output = RedactionSessionOutput::new(
            3,
            RedactedText::from_escaped("aggregate"),
            vec![item],
            RedactionSummary::complete(),
        );

        assert_eq!(
            output
                .resolve(RedactionHandle::new(3, 0))
                .expect("matching private handle resolves")
                .text()
                .as_str(),
            "item"
        );
    }
}
