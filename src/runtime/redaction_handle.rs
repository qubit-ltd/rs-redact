// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Opaque references to one item published by a completed transaction.
// qubit-style: allow multiple-public-types

/// Opaque reference to one redacted item produced during a session transaction.
///
/// A handle intentionally has no text formatting implementation. Call
/// [`crate::RedactionSessionOutput::resolve`] after `finish()` publishes the
/// transaction to obtain its safe text.
///
/// ```compile_fail
/// use qubit_redact::Redactor;
///
/// let mut session = Redactor::strict().session();
/// let handle = session.redact_field("password", "raw-secret");
/// let _ = format!("{handle}");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RedactionHandle {
    pub(super) transaction_id: u64,
    pub(super) item_index: usize,
}

impl RedactionHandle {
    /// Creates a handle for one transaction-owned item.
    #[must_use]
    pub(super) const fn new(transaction_id: u64, item_index: usize) -> Self {
        Self {
            transaction_id,
            item_index,
        }
    }
}

/// Explains why a transaction output cannot resolve a handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionHandleError {
    /// The handle was created by a different session transaction.
    DifferentTransaction,
    /// The handle points outside the transaction's published item range.
    MissingItem,
}
