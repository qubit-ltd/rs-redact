// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy borrowed view of a string-valued map-like container.

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
    RedactMapValue,
    RedactedText,
    RedactionPolicy,
};

/// A lazy map view that classifies values by their runtime keys.
#[must_use = "format or serialize the redacted map view"]
pub struct RedactedMap<'a, M: ?Sized> {
    /// Map borrowed without traversal.
    map: &'a M,
    /// Immutable policy snapshot used during formatting.
    policy: RedactionPolicy,
}

impl<'a, M: ?Sized> RedactedMap<'a, M> {
    /// Creates a lazy map view without traversing or cloning the map.
    ///
    /// # Parameters
    ///
    /// * `map` - String-valued map-like container to borrow.
    /// * `policy` - Complete policy snapshot owned by the view.
    ///
    /// # Returns
    ///
    /// A lazy borrowed map view.
    #[inline(always)]
    pub const fn new(map: &'a M, policy: RedactionPolicy) -> Self {
        Self { map, policy }
    }
}

impl<M: RedactMapValue + ?Sized> Debug for RedactedMap<'_, M> {
    /// Formats the map by classifying every value with its corresponding key.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.map.fmt_redacted_map(&self.policy, formatter)
    }
}

impl<M: RedactMapValue + ?Sized> Display for RedactedMap<'_, M> {
    /// Formats compact redacted debug output and escapes it for plain-text
    /// logs.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let redacted = format!("{self:?}");
        let safe = RedactedText::new(Cow::Owned(redacted)).escape_for_log();
        Display::fmt(&safe, formatter)
    }
}
