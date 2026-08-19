// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redacted representation of a plain or optional textual field.

use std::borrow::Cow;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;

use crate::MaskingPolicy;
use crate::Sensitivity;
use crate::output::MaskedValue;

/// Redacted text retaining its original plain or optional container shape.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of any borrowed redacted text stored by the value.
#[derive(Clone, PartialEq, Eq)]
pub enum RedactedValue<'a> {
    /// A plain textual value.
    Text(
        /// Masked text, borrowed when the masking policy permits it.
        MaskedValue<'a>,
    ),
    /// A present optional textual value.
    Some(
        /// Masked contents of the present option.
        MaskedValue<'a>,
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
    /// A plain redacted value containing the configured opaque replacement.
    #[inline(always)]
    #[must_use]
    pub fn opaque(level: Sensitivity, masking: &MaskingPolicy) -> Self {
        let replacement = masking.mask_opaque(level).to_owned();
        Self::Text(MaskedValue::new(Cow::Owned(replacement)))
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
            Self::Some(text) => formatter.debug_tuple("Some").field(&text.as_str()).finish(),
            Self::None => formatter.write_str("None"),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for RedactedValue<'_> {
    /// Preserves the original plain or optional container shape.
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
