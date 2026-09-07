// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Explicit lazy Display adaptation for a level-marked domain field.

use std::fmt;

#[cfg(any(feature = "serde", feature = "json"))]
use serde::Serializer;

use crate::RedactionWriter;
use crate::Sensitivity;
use crate::domain::RedactLevelValue;

/// Internal field adapter selecting a textual scalar representation.
///
/// # Type Parameters
///
/// - `'value`: Borrow of the source retained without formatting.
/// - `T`: Source whose Display implementation supplies the scalar text.
#[doc(hidden)]
pub struct DisplayValue<'value, T: ?Sized>(
    /// Raw source borrowed without formatting until explicit-level admission.
    &'value T,
);

impl<'value, T: ?Sized> DisplayValue<'value, T> {
    /// Borrows a value without invoking its formatter.
    ///
    /// # Parameters
    ///
    /// - `value`: Source whose `Display` implementation is selected lazily.
    ///
    /// # Returns
    ///
    /// A borrowed explicit-text adapter that has not formatted the source.
    #[must_use]
    #[inline(always)]
    pub fn new(value: &'value T) -> Self {
        Self(value)
    }
}

impl<T: fmt::Display + ?Sized> fmt::Debug for DisplayValue<'_, T> {
    /// Exposes Display only when the bounded writer requests the raw value.
    ///
    /// # Errors
    ///
    /// Propagates the underlying Display formatter error.
    ///
    /// # Parameters
    ///
    /// - `formatter`: Destination requesting the explicit textual
    ///   representation.
    ///
    /// # Returns
    ///
    /// Success after the selected Display representation is written.
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(value) = self;
        fmt::Display::fmt(value, formatter)
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for DisplayValue<'_, T> {
    /// Delegates the explicitly selected string representation.
    ///
    /// # Errors
    ///
    /// Propagates the underlying Display formatter error.
    ///
    /// # Parameters
    ///
    /// - `formatter`: Destination requesting the explicit textual
    ///   representation.
    ///
    /// # Returns
    ///
    /// Success after the selected Display representation is written.
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

impl<T: fmt::Display + ?Sized> crate::domain::LevelValueSealed for DisplayValue<'_, T> {}
impl<T: fmt::Display + ?Sized> RedactLevelValue for DisplayValue<'_, T> {
    /// Applies the exact level through the existing bounded scalar writer.
    ///
    /// # Parameters
    ///
    /// - `writer`: Active bounded redaction destination.
    /// - `level`: Explicit sensitivity applied before requesting the source
    ///   text.
    #[inline(always)]
    fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity) {
        writer.write_level_scalar(level, self);
    }
}

#[cfg(any(feature = "serde", feature = "json"))]
impl<T: fmt::Display + ?Sized> super::RedactLevelSerialize for DisplayValue<'_, T> {
    /// Serializes the chosen textual representation under the shared budget.
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
    /// - `serializer`: Destination receiving the admitted textual scalar.
    /// - `policy`: Immutable redaction snapshot.
    /// - `level`: Explicit sensitivity controlling access and masking.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline(always)]
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &crate::RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        super::redact_level_serialize::serialize_display_text(self, serializer, policy, level)
    }
}
