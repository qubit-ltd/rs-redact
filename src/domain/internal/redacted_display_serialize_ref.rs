// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Owned adapter state for a borrowed Display value and policy.

use std::fmt::Display;

use crate::RedactionPolicy;
use crate::Sensitivity;

/// Keeps the textual adapter alive for the complete field serialization.
#[doc(hidden)]
pub struct RedactedDisplaySerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed raw field, never formatted at construction.
    value: &'value T,
    /// Parent serialization policy.
    policy: &'policy RedactionPolicy,
    /// Final level declared on the field.
    level: Sensitivity,
}

impl<'value, 'policy, T: ?Sized> RedactedDisplaySerializeRef<'value, 'policy, T> {
    /// Captures the raw reference and field decision without invoking Display.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed source accessed only during serialization.
    /// - `policy`: Immutable policy borrowed independently of the source.
    /// - `level`: Explicit sensitivity applied to the textual scalar.
    ///
    /// # Returns
    ///
    /// A lazy adapter retaining the supplied source and policy references.
    #[must_use]
    #[inline(always)]
    pub fn new(value: &'value T, policy: &'policy RedactionPolicy, level: Sensitivity) -> Self {
        Self { value, policy, level }
    }
}

impl<T: Display + ?Sized> serde::Serialize for RedactedDisplaySerializeRef<'_, '_, T> {
    /// Executes one bounded textual scalar serialization.
    ///
    /// # Errors
    ///
    /// Propagates payload admission or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the result and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        super::redact_level_serialize::serialize_display_text(self.value, serializer, self.policy, self.level)
    }
}
