// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed, policy-snapshot view of a domain object.

use std::fmt::{
    self,
    Debug,
    Display,
    Formatter,
    Write as _,
};

use crate::{
    BoundedRedactedDisplay,
    LogOutputLimit,
    Redact,
    RedactionPolicy,
    text::internal::LogEscapeWriter,
};

/// A lazy non-destructive redacted view of a domain object.
///
/// The view borrows the original object and owns a cheap clone of the complete
/// policy. Creating it does not inspect, clone, or modify object fields.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed domain object.
/// * `T` - Domain-object type rendered or serialized through redaction.
#[must_use = "format or serialize the redacted view"]
pub struct Redacted<'a, T: ?Sized> {
    /// Domain object rendered through this view.
    value: &'a T,
    /// Immutable policy snapshot used for every formatting operation.
    policy: RedactionPolicy,
}

impl<'a, T: ?Sized> Redacted<'a, T> {
    /// Creates a redacted view from a borrowed object and an owned policy.
    ///
    /// # Parameters
    ///
    /// * `value` - Domain object to borrow without inspecting its fields.
    /// * `policy` - Complete policy snapshot owned by the view.
    ///
    /// # Returns
    ///
    /// A lazy redacted view.
    #[inline(always)]
    pub(crate) const fn new(value: &'a T, policy: RedactionPolicy) -> Self {
        Self { value, policy }
    }

    /// Converts this view into a byte-bounded, log-safe display adapter.
    ///
    /// # Parameters
    ///
    /// * `limit` - Maximum rendered bytes including any truncation marker.
    ///
    /// # Returns
    ///
    /// A display-only adapter that owns this redacted view.
    #[inline(always)]
    pub const fn with_output_limit(
        self,
        limit: LogOutputLimit,
    ) -> BoundedRedactedDisplay<Self> {
        BoundedRedactedDisplay::new(self, limit)
    }

    /// Converts this view into a byte-bounded display adapter using its policy.
    ///
    /// # Returns
    ///
    /// A display-only adapter bounded by this view's diagnostic output budget.
    #[must_use = "format the bounded redacted display adapter"]
    #[inline]
    pub fn with_policy_output_limit(self) -> BoundedRedactedDisplay<Self> {
        let limit = LogOutputLimit::from(self.policy.diagnostic_budget());
        BoundedRedactedDisplay::new(self, limit)
    }

    /// Returns the borrowed domain value to crate-internal adapters.
    ///
    /// # Returns
    ///
    /// The original domain value borrowed for the view's lifetime.
    #[cfg(feature = "serde")]
    #[inline(always)]
    pub(crate) const fn value(&self) -> &'a T {
        self.value
    }

    /// Returns the policy snapshot to crate-internal adapters.
    ///
    /// # Returns
    ///
    /// The immutable policy snapshot owned by this view.
    #[cfg(feature = "serde")]
    #[inline(always)]
    pub(crate) const fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }
}

#[cfg(feature = "serde")]
impl<T: crate::domain::RedactSerialize + ?Sized> serde::Serialize
    for Redacted<'_, T>
{
    /// Delegates serialization to the derived redaction hook.
    ///
    /// # Type Parameters
    ///
    /// * `S` - Destination Serde serializer type.
    ///
    /// # Parameters
    ///
    /// * `serializer` - Destination Serde serializer.
    ///
    /// # Returns
    ///
    /// The derived hook's successful output.
    ///
    /// # Errors
    ///
    /// Returns the derived hook's serialization error unchanged.
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value().serialize_redacted(self.policy(), serializer)
    }
}

impl<T: Redact + ?Sized> Debug for Redacted<'_, T> {
    /// Writes the object's redacted representation while preserving formatter
    /// flags such as alternate pretty formatting.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context whose flags are passed to
    ///   the object's redaction hook.
    ///
    /// # Returns
    ///
    /// The formatter result for the complete redacted representation.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the object cannot write its complete
    /// redacted representation.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.value.fmt_redacted(&self.policy, formatter)
    }
}

impl<T: Redact + ?Sized> Display for Redacted<'_, T> {
    /// Writes a compact redacted debug representation escaped for logs.
    ///
    /// Redacted debug output is escaped directly into the destination without
    /// constructing an intermediate [`String`]. This implementation never
    /// calls the original object's `Display`.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the escaped redacted representation.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination cannot accept the complete
    /// log-safe representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = LogEscapeWriter::new(formatter);
        write!(&mut writer, "{self:?}")
    }
}
