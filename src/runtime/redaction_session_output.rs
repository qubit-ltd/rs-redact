// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Atomically published output from one redaction session.

use crate::RedactionHandle;
use crate::RedactionHandleError;
use crate::RedactionSummary;
use crate::RedactionTextOutput;

/// Final output published after a session commits successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchPublication {
    transaction_id: u64,
    items: Vec<RedactionTextOutput>,
    summary: RedactionSummary,
}

impl BatchPublication {
    /// Creates a published session output.
    pub(crate) fn new(
        transaction_id: u64,
        items: Vec<RedactionTextOutput>,
        summary: RedactionSummary,
    ) -> Self {
        Self {
            transaction_id,
            items,
            summary,
        }
    }

    /// Returns the aggregate summary.
    #[must_use]
    pub const fn summary(&self) -> &RedactionSummary {
        &self.summary
    }

    /// Consumes this published transaction and returns the item selected by
    /// `handle` without cloning its final redacted text.
    ///
    /// Returns [`RedactionHandleError::DifferentTransaction`] when `handle`
    /// originated from another transaction and
    /// [`RedactionHandleError::MissingItem`] when its item index is invalid.
    pub fn into_resolved(
        self,
        handle: RedactionHandle,
    ) -> Result<RedactionTextOutput, RedactionHandleError> {
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
    pub fn resolve(
        &self,
        handle: RedactionHandle,
    ) -> Result<&RedactionTextOutput, RedactionHandleError> {
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
    use super::BatchPublication;
    use super::RedactionTextOutput;
    use crate::RedactedText;
    use crate::RedactionSummary;

    /// An invalid same-transaction index is reported distinctly from an
    /// ordinary cross-transaction handle mismatch.
    #[test]
    fn resolve_reports_missing_same_transaction_item() {
        let output = BatchPublication::new(
            7,
            Vec::new(),
            RedactionSummary::complete(),
        );

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
        let item = RedactionTextOutput::new(
            RedactedText::from_escaped("item"),
            RedactionSummary::complete(),
        );
        let output = BatchPublication::new(
            3,
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
