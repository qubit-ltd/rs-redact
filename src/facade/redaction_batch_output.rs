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

/// Published independently resolvable results from one
/// [`crate::RedactionBatch`].
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let mut batch = Redactor::strict().batch();
/// let handle = batch.redact_field("password", "raw-secret");
/// let output = batch.finish();
/// assert!(output.resolve(handle).is_ok());
/// ```
pub struct RedactionBatchOutput {
    /// Private publication that owns the batch identity, items, and summary.
    output: BatchPublication,
}

impl RedactionBatchOutput {
    /// Creates public batch output from one completed private publication.
    #[must_use]
    pub(crate) const fn from_publication(output: BatchPublication) -> Self {
        Self { output }
    }

    /// Returns the aggregate accounting summary for the batch.
    #[must_use]
    #[inline(always)]
    pub const fn summary(&self) -> &crate::RedactionSummary {
        self.output.summary()
    }

    /// Resolves `handle` without cloning its text.
    ///
    /// Returns [`RedactionBatchHandleError::DifferentBatch`] when `handle`
    /// was created by another batch, or `MissingItem` for an invalid index.
    pub fn resolve(&self, handle: RedactionBatchHandle) -> Result<&RedactionTextOutput, RedactionBatchHandleError> {
        self.output
            .resolve(RedactionHandle::new(handle.batch_id, handle.item_index))
            .map_err(|error| match error {
                crate::RedactionHandleError::DifferentTransaction => RedactionBatchHandleError::DifferentBatch,
                crate::RedactionHandleError::MissingItem => RedactionBatchHandleError::MissingItem,
            })
    }

    /// Consumes the output and moves the text selected by `handle` out of it.
    ///
    /// Returns the same errors as [`Self::resolve`].
    pub fn into_resolved(self, handle: RedactionBatchHandle) -> Result<RedactionTextOutput, RedactionBatchHandleError> {
        self.output
            .into_resolved(RedactionHandle::new(handle.batch_id, handle.item_index))
            .map_err(|error| match error {
                crate::RedactionHandleError::DifferentTransaction => RedactionBatchHandleError::DifferentBatch,
                crate::RedactionHandleError::MissingItem => RedactionBatchHandleError::MissingItem,
            })
    }
}
