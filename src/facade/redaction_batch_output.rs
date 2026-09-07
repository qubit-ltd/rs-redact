// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Published independently resolvable batch results.

use super::RedactionBatchHandle;
use super::RedactionBatchHandleError;
use crate::RedactionTextOutput;
use crate::runtime::BatchPublication;
use crate::runtime::RedactionHandle;

/// Crate-private publication used to build fail-closed batch diagnostics.
pub(crate) struct RedactionBatchOutput {
    /// Private publication that owns the batch identity, items, and summary.
    output: BatchPublication,
}

impl RedactionBatchOutput {
    /// Wraps a completed runtime publication for crate-private batch
    /// resolution.
    ///
    /// # Parameters
    ///
    /// - `output`: Runtime publication owning item identities, output, and
    ///   accounting.
    ///
    /// # Returns
    ///
    /// A crate-private facade preserving the complete publication.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn from_publication(output: BatchPublication) -> Self {
        Self { output }
    }

    /// Returns the aggregate accounting summary for the batch.
    ///
    /// # Returns
    ///
    /// The immutable aggregate summary of this batch publication.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn summary(&self) -> &crate::RedactionSummary {
        self.output.summary()
    }

    /// Resolves `handle` without cloning its text.
    ///
    /// Returns [`RedactionBatchHandleError::DifferentBatch`] when `handle`
    /// was created by another batch, or `MissingItem` for an invalid index.
    ///
    /// # Parameters
    ///
    /// - `handle`: Opaque capability to resolve against this publication.
    ///
    /// # Returns
    ///
    /// The borrowed item output, including its own completion and accounting.
    ///
    /// # Errors
    ///
    /// Returns DifferentBatch for a foreign identity or MissingItem for an
    /// invalid index.
    #[inline]
    pub(crate) fn resolve(
        &self,
        handle: RedactionBatchHandle,
    ) -> Result<&RedactionTextOutput, RedactionBatchHandleError> {
        self.output
            .resolve(RedactionHandle::new(handle.batch_id, handle.item_index))
            .map_err(|error| match error {
                crate::RedactionHandleError::DifferentTransaction => RedactionBatchHandleError::DifferentBatch,
                crate::RedactionHandleError::MissingItem => RedactionBatchHandleError::MissingItem,
            })
    }
}

// These regressions forge an invalid index through facade-private handle
// fields. Keep them local instead of widening the public or crate-visible
// handle contract.
#[cfg(test)]
mod tests {
    use super::RedactionBatchHandle;
    use super::RedactionBatchHandleError;
    use crate::Redactor;

    /// The public facade preserves the same-batch missing-item distinction.
    #[test]
    fn test_resolve_reports_missing_item_for_same_batch_invalid_index() {
        let mut batch = Redactor::standard().batch();
        let valid = batch.redact_field("name", "Ada");
        let missing = RedactionBatchHandle {
            batch_id: valid.batch_id,
            item_index: usize::MAX,
        };
        let output = batch.finish();

        assert!(matches!(
            output.resolve(missing),
            Err(RedactionBatchHandleError::MissingItem),
        ));
    }
}
