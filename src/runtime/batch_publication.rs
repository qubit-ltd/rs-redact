// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Atomically published output from one redaction batch.

use crate::RedactionHandle;
use crate::RedactionHandleError;
use crate::RedactionSummary;
use crate::RedactionTextOutput;

/// Final output published after a batch commits successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchPublication {
    /// Identity shared by every handle created before publication.
    transaction_id: u64,
    /// Independently resolvable final item outputs.
    items: Vec<RedactionTextOutput>,
    /// Aggregate accounting for the complete batch.
    summary: RedactionSummary,
}

impl BatchPublication {
    /// Creates output for the completed batch identity and staged items.
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

    /// Returns aggregate accounting across all published batch items.
    #[must_use]
    pub(crate) const fn summary(&self) -> &RedactionSummary {
        &self.summary
    }

    /// Moves the item selected by `handle` without cloning its final text.
    ///
    /// Returns [`RedactionHandleError::DifferentTransaction`] for another
    /// batch identity and [`RedactionHandleError::MissingItem`] for an invalid
    /// index in this batch.
    pub(crate) fn into_resolved(
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

    /// Borrows the item selected by `handle` without cloning its final text.
    ///
    /// Returns [`RedactionHandleError::DifferentTransaction`] for another
    /// batch identity and [`RedactionHandleError::MissingItem`] for an invalid
    /// index in this batch.
    pub(crate) fn resolve(
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
    use super::BatchPublication;
    use crate::RedactedText;
    use crate::RedactionHandle;
    use crate::RedactionHandleError;
    use crate::RedactionSummary;
    use crate::RedactionTextOutput;

    /// An invalid same-batch index is reported distinctly from a cross-batch
    /// handle.
    #[test]
    fn test_resolve_reports_missing_same_batch_item() {
        let output = BatchPublication::new(7, Vec::new(), RedactionSummary::complete());

        assert_eq!(*output.summary(), RedactionSummary::complete());
        assert_eq!(
            output.resolve(RedactionHandle::new(7, 0)),
            Err(RedactionHandleError::MissingItem)
        );
    }

    /// Valid items resolve by insertion index without exposing that index
    /// publicly.
    #[test]
    fn test_resolve_returns_published_batch_item() {
        let item = RedactionTextOutput::new(
            RedactedText::from_escaped("item"),
            RedactionSummary::complete(),
        );
        let output = BatchPublication::new(3, vec![item], RedactionSummary::complete());

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
