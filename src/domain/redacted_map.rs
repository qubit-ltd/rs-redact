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
    marker::PhantomData,
};

use crate::{
    RedactMapValue,
    RedactedText,
    RedactionPolicy,
};

/// A lazy map view that classifies values by their runtime keys.
#[must_use = "format or serialize the redacted map view"]
pub struct RedactedMap<'a, M: ?Sized, K: ?Sized = String, V: ?Sized = String> {
    /// Map borrowed without traversal.
    map: &'a M,
    /// Immutable policy snapshot used during formatting.
    policy: RedactionPolicy,
    /// Associates the view with the map entry types without storing them.
    marker: PhantomData<fn() -> (*const K, *const V)>,
}

impl<'a, M: ?Sized, K: ?Sized, V: ?Sized> RedactedMap<'a, M, K, V> {
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
        Self {
            map,
            policy,
            marker: PhantomData,
        }
    }
}

impl<M: RedactMapValue<K, V> + ?Sized, K: ?Sized, V: ?Sized> Debug
    for RedactedMap<'_, M, K, V>
{
    /// Formats the map by classifying every value with its corresponding key.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination debug formatter.
    ///
    /// # Returns
    ///
    /// The formatter result for the complete map.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination rejects an entry or the
    /// completed map.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.map.fmt_redacted_map(&self.policy, formatter)
    }
}

impl<M: RedactMapValue<K, V> + ?Sized, K: ?Sized, V: ?Sized> Display
    for RedactedMap<'_, M, K, V>
{
    /// Formats compact redacted debug output and escapes it for plain-text
    /// logs.
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
    /// Returns [`fmt::Error`] when the destination rejects the complete
    /// log-safe representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let redacted = format!("{self:?}");
        let safe = RedactedText::new(Cow::Owned(redacted)).escape_for_log();
        Display::fmt(&safe, formatter)
    }
}

#[cfg(feature = "serde")]
impl<M: crate::domain::RedactMapSerialize<K, V> + ?Sized, K: ?Sized, V: ?Sized>
    serde::Serialize for RedactedMap<'_, M, K, V>
{
    /// Serializes values after classifying each one by its runtime key.
    ///
    /// # Parameters
    ///
    /// * `serializer` - Destination Serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's successful map output.
    ///
    /// # Errors
    ///
    /// Returns the first entry or destination serialization error unchanged.
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.map.serialize_redacted_map(&self.policy, serializer)
    }
}
