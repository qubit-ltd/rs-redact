// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy redaction view selected by an external field key.

use std::{
    fmt::Write as _,
    fmt::{
        self,
        Debug,
        Display,
        Formatter,
    },
};

use crate::{
    Redact,
    RedactValue,
    RedactionPolicy,
    text::internal::LogEscapeWriter,
};

/// A borrowed value rendered according to a separate field key.
///
/// The key is used only to select a policy rule. The view itself renders or
/// serializes the value, and owns an immutable snapshot of that policy.
#[must_use = "format or serialize the keyed redaction view"]
pub struct RedactedKeyedValue<'a, T: ?Sized> {
    /// Field name used for policy classification.
    key: &'a str,
    /// Value represented by this view.
    value: &'a T,
    /// Immutable policy snapshot used by every output protocol.
    policy: RedactionPolicy,
}

impl<'a, T: ?Sized> RedactedKeyedValue<'a, T> {
    /// Creates a keyed view from borrowed inputs and an owned policy snapshot.
    ///
    /// # Parameters
    ///
    /// * `key` - Field name used only for policy classification.
    /// * `value` - Value to render or serialize lazily.
    /// * `policy` - Complete policy snapshot owned by this view.
    ///
    /// # Returns
    ///
    /// A view that never modifies the original value.
    #[must_use = "format or serialize the keyed redaction view"]
    #[inline(always)]
    pub const fn new(
        key: &'a str,
        value: &'a T,
        policy: RedactionPolicy,
    ) -> Self {
        Self { key, value, policy }
    }

    /// Returns the external field key used by this view.
    ///
    /// # Returns
    ///
    /// The unchanged policy lookup key.
    #[must_use]
    #[inline(always)]
    pub const fn key(&self) -> &'a str {
        self.key
    }
}

impl<T: Redact + RedactValue + ?Sized> Debug for RedactedKeyedValue<'_, T> {
    /// Formats the value through its selected field classification.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatter whose flags are preserved.
    ///
    /// # Returns
    ///
    /// The complete redacted debug result.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter cannot accept the
    /// complete representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self.policy.sensitivity_for(self.key) {
            Some(level) => Debug::fmt(
                &self.value.redact_value(level, self.policy.masking()),
                formatter,
            ),
            None => self.value.fmt_redacted(&self.policy, formatter),
        }
    }
}

impl<T: Redact + RedactValue + ?Sized> Display for RedactedKeyedValue<'_, T> {
    /// Formats the selected redacted representation for a plain-text log.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination plain-text log boundary.
    ///
    /// # Returns
    ///
    /// The complete escaped redacted representation.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter cannot accept the
    /// complete escaped representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = LogEscapeWriter::new(formatter);
        write!(&mut writer, "{self:?}")
    }
}

#[cfg(feature = "serde")]
impl<T: RedactValue + crate::domain::RedactSerialize + ?Sized> serde::Serialize
    for RedactedKeyedValue<'_, T>
{
    /// Serializes the value through its selected field classification.
    ///
    /// # Parameters
    ///
    /// * `serializer` - Destination serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's successful redacted output.
    ///
    /// # Errors
    ///
    /// Returns the destination serializer's error unchanged.
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.policy.sensitivity_for(self.key) {
            Some(level) => serde::Serialize::serialize(
                &self.value.redact_value(level, self.policy.masking()),
                serializer,
            ),
            None => crate::domain::RedactSerialize::serialize_redacted(
                self.value,
                &self.policy,
                serializer,
            ),
        }
    }
}
