// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redacted representation of a plain or optional textual field.

use std::{
    borrow::Cow,
    fmt::{
        self,
        Debug,
        Display,
        Formatter,
    },
};

use crate::{
    LogSafeText,
    MaskingPolicy,
    RedactedText,
    Sensitivity,
};

/// Redacted text retaining its original plain or optional container shape.
#[must_use = "format or otherwise consume the redacted value"]
#[derive(Clone, PartialEq, Eq)]
pub enum RedactedValue<'a> {
    /// A plain textual value.
    Text(
        /// Masked text, borrowed when the masking policy permits it.
        RedactedText<'a>,
    ),
    /// A present optional textual value.
    Some(
        /// Masked contents of the present option.
        RedactedText<'a>,
    ),
    /// An absent optional textual value.
    None,
}

impl<'a> RedactedValue<'a> {
    /// Creates an opaque replacement for a sensitive non-text value.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the complete replacement.
    /// * `masking` - Complete masking configuration.
    ///
    /// # Returns
    ///
    /// A plain redacted value that borrows the configured opaque replacement.
    #[inline(always)]
    pub fn opaque(level: Sensitivity, masking: &'a MaskingPolicy) -> Self {
        Self::Text(RedactedText::new(Cow::Borrowed(masking.mask_opaque(level))))
    }
}

impl Debug for RedactedValue<'_> {
    /// Writes the masked text while retaining normal text and option shapes.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the complete redacted value.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination cannot accept the complete
    /// representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => Debug::fmt(text.as_str(), formatter),
            Self::Some(text) => {
                formatter.debug_tuple("Some").field(&text.as_str()).finish()
            }
            Self::None => formatter.write_str("None"),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for RedactedValue<'_> {
    /// Preserves the original plain or optional container shape.
    ///
    /// # Parameters
    ///
    /// * `serializer` - Destination Serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's successful text or option output.
    ///
    /// # Errors
    ///
    /// Returns the destination serializer's error unchanged.
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Text(text) => serializer.serialize_str(text.as_str()),
            Self::Some(text) => serializer.serialize_some(text.as_str()),
            Self::None => serializer.serialize_none(),
        }
    }
}

impl Display for RedactedValue<'_> {
    /// Writes masked contents escaped for a plain-text log boundary.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the complete log-safe value.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination cannot accept the complete
    /// log-safe representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => Display::fmt(&log_safe(text), formatter),
            Self::Some(text) => {
                formatter.write_str("Some(")?;
                Display::fmt(&log_safe(text), formatter)?;
                formatter.write_str(")")
            }
            Self::None => formatter.write_str("None"),
        }
    }
}

/// Borrows masked text and escapes it for a plain-text log boundary.
///
/// # Parameters
///
/// * `text` - Masked text to render safely.
///
/// # Returns
///
/// A log-safe view that borrows `text` when it contains no unsafe controls.
#[inline(always)]
fn log_safe<'a>(text: &'a RedactedText<'_>) -> LogSafeText<'a> {
    RedactedText::new(Cow::Borrowed(text.as_str())).escape_for_log()
}
