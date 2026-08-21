// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Opaque capabilities for unpublished batch items.

/// Opaque reference to one unpublished item in a [`crate::RedactionBatch`].
///
/// ```compile_fail
/// use qubit_redact::Redactor;
///
/// let mut batch = Redactor::strict().batch();
/// let handle = batch.redact_field("password", "raw-secret");
/// let _ = format!("{handle}");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RedactionBatchHandle {
    /// Identity of the batch that created this capability.
    pub(super) batch_id: u64,
    /// Insertion position of the protected item within its batch.
    pub(super) item_index: usize,
}
