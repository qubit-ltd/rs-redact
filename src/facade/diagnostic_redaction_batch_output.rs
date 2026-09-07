// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Published independently resolvable batch results.

use super::DiagnosticRedactionHandle;
use super::DiagnosticRedactionHandleError;
use crate::RedactionTextOutput;
use crate::runtime::BatchPublication;
use crate::runtime::RedactionHandle;

/// Crate-private publication used to build fail-closed batch diagnostics.
pub(crate) struct DiagnosticRedactionBatchOutput {
    /// Private publication that owns the batch identity, items, and summary.
    output: BatchPublication,
}

impl DiagnosticRedactionBatchOutput {
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
    /// Returns [`DiagnosticRedactionHandleError::DifferentBatch`] when `handle`
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
        handle: DiagnosticRedactionHandle,
    ) -> Result<&RedactionTextOutput, DiagnosticRedactionHandleError> {
        self.output
            .resolve(RedactionHandle::new(handle.batch_id, handle.item_index))
            .map_err(|error| match error {
                crate::RedactionHandleError::DifferentTransaction => {
                    DiagnosticRedactionHandleError::DifferentBatch
                }
                crate::RedactionHandleError::MissingItem => {
                    DiagnosticRedactionHandleError::MissingItem
                }
            })
    }
}

// These regressions forge an invalid index through facade-private handle
// fields. Keep them local instead of widening the public or crate-visible
// handle contract.
#[cfg(test)]
mod tests {
    use super::DiagnosticRedactionHandle;
    use super::DiagnosticRedactionHandleError;
    use crate::Redactor;

    /// The public facade preserves the same-batch missing-item distinction.
    #[test]
    fn test_resolve_reports_missing_item_for_same_batch_invalid_index() {
        let mut batch = Redactor::standard().diagnostic_batch();
        let valid = batch.redact_field("name", "Ada");
        let missing = DiagnosticRedactionHandle {
            batch_id: valid.batch_id,
            item_index: usize::MAX,
        };
        let output = batch.finish_publication();

        assert!(matches!(
            output.resolve(missing),
            Err(DiagnosticRedactionHandleError::MissingItem),
        ));
    }
}
