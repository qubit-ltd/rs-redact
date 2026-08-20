// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Lifecycle phase of one unpublished transaction.

/// Lifecycle phase of one unpublished transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransactionPhase {
    /// The transaction can still admit and stage output.
    Active,
    /// The shared output budget is closed to all later operations.
    OutputExhausted,
}
