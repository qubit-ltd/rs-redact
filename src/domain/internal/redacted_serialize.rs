// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed policy-preserving wrapper for nested serialization.

use crate::{
    RedactionPolicy,
    domain::RedactSerialize,
};

/// A nested value paired with the current explicit policy.
#[doc(hidden)]
#[must_use = "serialize the adapter to produce redacted output"]
pub struct RedactedSerialize<'a, T: ?Sized> {
    /// Nested value to serialize.
    value: &'a T,
    /// Policy borrowed from the outer serialization call.
    policy: &'a RedactionPolicy,
}

impl<'a, T: ?Sized> RedactedSerialize<'a, T> {
    /// Creates a nested serialization wrapper without cloning either input.
    ///
    /// # Parameters
    ///
    /// * `value` - Nested domain value.
    /// * `policy` - Current explicit redaction policy.
    ///
    /// # Returns
    ///
    /// A borrowed nested wrapper.
    #[inline(always)]
    pub const fn new(value: &'a T, policy: &'a RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

impl<T: RedactSerialize + ?Sized> serde::Serialize
    for RedactedSerialize<'_, T>
{
    /// Delegates serialization to the nested redaction hook.
    ///
    /// # Parameters
    ///
    /// * `serializer` - Destination Serde serializer.
    ///
    /// # Returns
    ///
    /// The nested redaction hook's successful output.
    ///
    /// # Errors
    ///
    /// Returns the nested redaction hook's error unchanged.
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value.serialize_redacted(self.policy, serializer)
    }
}
