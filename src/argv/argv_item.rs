// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! One argument and the sensitivity known by its caller.

use std::ffi::OsStr;
use std::fmt;

use crate::Sensitivity;

/// A borrowed argument with optional authoritative sensitivity metadata.
///
/// Plain items may be inspected by
/// [`super::ArgvRedactor::redact_heuristically`]. Sensitive items are always
/// masked at their explicit level and never interpreted as command-line syntax.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed operating-system argument.
#[derive(Clone, Copy)]
pub struct ArgvItem<'a> {
    /// Original operating-system argument value.
    value: &'a OsStr,
    /// Authoritative sensitivity supplied by the caller, when known.
    sensitivity: Option<Sensitivity>,
}

impl fmt::Debug for ArgvItem<'_> {
    /// Formats safe argument metadata without exposing the original value.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result from writing the safe metadata.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination rejects a write.

    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArgvItem")
            .field("value", &"<redacted>")
            .field("value_len", &self.value.as_encoded_bytes().len())
            .field("sensitivity", &self.sensitivity)
            .finish()
    }
}

impl<'a> ArgvItem<'a> {
    /// Creates an item with no caller-supplied sensitivity.
    ///
    /// # Parameters
    ///
    /// * `value` - Argument value that may be inspected by heuristic mode.
    ///
    /// # Returns
    ///
    /// A plain borrowed argument item.
    #[inline(always)]
    #[must_use]
    pub const fn plain(value: &'a OsStr) -> Self {
        Self {
            value,
            sensitivity: None,
        }
    }

    /// Creates an item whose value must be masked at `sensitivity`.
    ///
    /// # Parameters
    ///
    /// * `value` - Argument value to mask.
    /// * `sensitivity` - Authoritative masking level for the complete value.
    ///
    /// # Returns
    ///
    /// A sensitive borrowed argument item.
    #[inline(always)]
    #[must_use]
    pub const fn sensitive(value: &'a OsStr, sensitivity: Sensitivity) -> Self {
        Self {
            value,
            sensitivity: Some(sensitivity),
        }
    }

    /// Returns the original operating-system argument.
    ///
    /// # Returns
    ///
    /// The borrowed argument value.
    #[inline(always)]
    pub(super) const fn value(&self) -> &'a OsStr {
        self.value
    }

    /// Returns the caller-supplied sensitivity, when present.
    ///
    /// # Returns
    ///
    /// `Some(level)` for an explicitly sensitive item, or `None` for a plain
    /// item.
    #[must_use]
    #[inline(always)]
    pub(super) const fn sensitivity(&self) -> Option<Sensitivity> {
        self.sensitivity
    }
}
