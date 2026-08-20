// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal field-level values produced by masking.

use std::borrow::Cow;

use super::RedactedText;
use super::log_escape::escape_log_control_characters;

/// An internal value that has passed through field-sensitive masking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedValue<'a>(Cow<'a, str>);

impl<'a> MaskedValue<'a> {
    /// Creates typed redacted text from an already processed value.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn new(value: Cow<'a, str>) -> Self {
        Self(value)
    }

    /// Escapes the redacted contents for a plain-text boundary.
    #[inline]
    #[must_use]
    pub fn escape_for_log(self) -> RedactedText {
        RedactedText::from_escaped(escape_log_control_characters(self.0).into_owned())
    }

    /// Borrows the underlying value for crate-internal HTTP adapters.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Converts the underlying value into an owned string for HTTP adapters.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub(crate) fn into_owned(self) -> String {
        self.0.into_owned()
    }

    /// Returns the underlying value to crate-internal adapters.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub(crate) fn into_inner(self) -> Cow<'a, str> {
        self.0
    }
}
