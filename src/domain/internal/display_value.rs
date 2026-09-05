// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Explicit lazy Display adaptation for a level-marked domain field.

use std::fmt;

use crate::RedactionWriter;
use crate::Sensitivity;
use crate::domain::RedactLevelValue;

/// Internal field adapter selecting a textual scalar representation.
#[doc(hidden)]
pub struct DisplayValue<'value, T: ?Sized>(&'value T);

impl<'value, T: ?Sized> DisplayValue<'value, T> {
    /// Borrows a value without invoking its formatter.
    pub fn new(value: &'value T) -> Self {
        Self(value)
    }
}

impl<T: fmt::Display + ?Sized> fmt::Debug for DisplayValue<'_, T> {
    /// Exposes Display only when the bounded writer requests the raw value.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(value) = self;
        fmt::Display::fmt(value, formatter)
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for DisplayValue<'_, T> {
    /// Delegates the explicitly selected string representation.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

impl<T: fmt::Display + ?Sized> crate::domain::LevelValueSealed for DisplayValue<'_, T> {}
impl<T: fmt::Display + ?Sized> RedactLevelValue for DisplayValue<'_, T> {
    /// Applies the exact level through the existing bounded scalar writer.
    fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity) {
        writer.write_level_scalar(level, self);
    }
}

#[cfg(any(feature = "serde", feature = "json"))]
impl<T: fmt::Display + ?Sized> super::RedactLevelSerialize for DisplayValue<'_, T> {
    /// Serializes the chosen textual representation under the shared budget.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &crate::RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        super::redact_level_serialize::serialize_display_text(self, serializer, policy, level)
    }
}
