// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal field-level values produced by masking.

use std::borrow::Cow;

/// An internal value that has passed through field-sensitive masking.
///
/// Retains borrowed pass-through text for `'a` or owns a policy-selected mask;
/// construction accepts only text already processed by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedValue<'a>(
    /// Borrowed pass-through text or an owned mask selected by policy.
    Cow<'a, str>,
);

impl<'a> MaskedValue<'a> {
    /// Creates typed redacted text from an already processed value.
    ///
    /// # Parameters
    ///
    /// - `value`: Text already processed by field-sensitive masking. Ownership
    ///   is transferred without cloning; borrowed text retains its lifetime
    ///   `'a`.
    ///
    /// # Returns
    ///
    /// A wrapper retaining the supplied borrowed or owned text without
    /// allocation.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn new(value: Cow<'a, str>) -> Self {
        Self(value)
    }

    /// Borrows the underlying value for crate-internal HTTP adapters.
    ///
    /// # Returns
    ///
    /// The masked text, valid while `self` is borrowed, without allocation.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Converts the underlying value into an owned string for HTTP adapters.
    ///
    /// # Returns
    ///
    /// The owned text, moving an existing string or cloning borrowed text.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub(crate) fn into_owned(self) -> String {
        self.0.into_owned()
    }

    /// Returns the underlying value to crate-internal adapters.
    ///
    /// # Returns
    ///
    /// The original borrowed or owned text, moved out without cloning.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub(crate) fn into_inner(self) -> Cow<'a, str> {
        self.0
    }
}
