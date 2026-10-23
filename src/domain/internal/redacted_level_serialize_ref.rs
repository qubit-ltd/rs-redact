// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed adapter for explicitly classified structured scalar values.

use serde::Serialize;
use serde::Serializer;

use super::redact_level_serialize::RedactLevelSerialize;
use super::redact_serialize_scope::serialize_structured;

/// Borrows a source value, policy, and explicit sensitivity for serialization.
///
/// The adapter retains these inputs without serializing the value during
/// construction. Its [`Serialize`] implementation applies the shared
/// structured serialization scope before delegating to the value's level
/// serializer.
///
/// # Type Parameters
///
/// - `T`: Source value implementing the internal level serialization contract.
#[doc(hidden)]
pub struct RedactedLevelSerializeRef<'value, 'policy, T: ?Sized> {
    /// Source value serialized only when the adapter is serialized.
    value: &'value T,
    /// Immutable policy controlling redaction and resource limits.
    policy: &'policy crate::RedactionPolicy,
    /// Sensitivity applied to scalar leaves emitted by the source value.
    level: crate::Sensitivity,
}

impl<'value, 'policy, T: ?Sized> RedactedLevelSerializeRef<'value, 'policy, T> {
    /// Retains a source value and its explicit sensitivity for later
    /// serialization.
    ///
    /// This constructor does not inspect or serialize `value`; those operations
    /// occur when the returned adapter is passed to a serializer.
    ///
    /// # Parameters
    ///
    /// - `value`: Source value borrowed for the adapter's lifetime.
    /// - `policy`: Immutable redaction and resource policy used during
    ///   serialization.
    /// - `level`: Sensitivity applied to scalar leaves in the serialized value.
    ///
    /// # Returns
    ///
    /// An adapter borrowing the source and policy without performing
    /// serialization.
    #[must_use]
    #[inline(always)]
    pub fn new(value: &'value T, policy: &'policy crate::RedactionPolicy, level: crate::Sensitivity) -> Self {
        Self { value, policy, level }
    }
}

impl<T: ?Sized + RedactLevelSerialize> Serialize for RedactedLevelSerializeRef<'_, '_, T> {
    /// Runs this borrowed adapter under the shared policy and resource scope.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Destination serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    ///
    /// # Returns
    ///
    /// The destination result after the value is serialized in the shared
    /// scope.
    ///
    /// # Errors
    ///
    /// Propagates admission failures and errors from the downstream serializer.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_structured(serializer, self.policy, |serializer| {
            self.value.serialize_redacted_level(serializer, self.policy, self.level)
        })
    }
}
