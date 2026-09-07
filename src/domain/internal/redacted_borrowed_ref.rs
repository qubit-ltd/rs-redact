// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy policy-carrying adapter for a reference serialization capability.

use serde::Serialize;
use serde::Serializer;

use super::RedactBorrowedSerialize;
use crate::RedactionPolicy;

/// Retains a source borrow whose nested serialization capability is
/// conditional.
///
/// # Type Parameters
///
/// - `'value`: Actual lifetime of the borrowed source.
/// - `'policy`: Lifetime of the independently borrowed policy.
/// - `T`: Source type; its reference capability is checked when serialized.
pub struct RedactedBorrowedRef<'value, 'policy, T: ?Sized> {
    /// Source observed only after serialization starts.
    value: &'value T,
    /// Snapshot used for the shared admission scope.
    policy: &'policy RedactionPolicy,
}

impl<'value, 'policy, T: ?Sized> RedactedBorrowedRef<'value, 'policy, T> {
    /// Retains both borrows without observing the source.
    ///
    /// # Parameters
    ///
    /// - `value`: Source borrowed for deferred serialization.
    /// - `policy`: Snapshot governing the deferred operation.
    ///
    /// # Returns
    ///
    /// A lazy adapter retaining the supplied references.
    #[must_use]
    #[inline(always)]
    pub const fn new(value: &'value T, policy: &'policy RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

impl<'value, T: ?Sized> Serialize for RedactedBorrowedRef<'value, '_, T>
where
    &'value T: RedactBorrowedSerialize,
{
    /// Delegates once to the source borrow under the retained policy.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Destination serializer defining the result and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    ///
    /// # Returns
    ///
    /// The destination result after visiting the borrowed source.
    ///
    /// # Errors
    ///
    /// Propagates admission and downstream serialization failures.
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize_borrowed(serializer, self.policy)
    }
}
