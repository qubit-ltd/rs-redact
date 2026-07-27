// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy borrowed view of a map whose values support recursive redaction.

use std::{
    fmt::{self, Debug, Display, Formatter, Write as _},
    marker::PhantomData,
};

use crate::{
    BoundedRedactedDisplay, LogOutputLimit, Redact, RedactValue, RedactedKeyedValue,
    RedactionPolicy, text::internal::LogEscapeWriter,
};

/// A lazy map view that classifies each value by its key before recursion.
///
/// Unknown and explicitly allowed keys delegate to the corresponding value's
/// [`Redact`] implementation. Sensitive keys mask the complete value through
/// [`RedactValue`].
#[must_use = "format the recursive keyed redaction view"]
pub struct RedactedKeyedMap<'a, M: ?Sized, K: ?Sized = String, V: ?Sized = String> {
    /// Map borrowed without traversal.
    map: &'a M,
    /// Immutable policy snapshot shared by every keyed value view.
    policy: RedactionPolicy,
    /// Associates the view with the map entry types without storing them.
    marker: PhantomData<fn() -> (*const K, *const V)>,
}

impl<'a, M: ?Sized, K: ?Sized, V: ?Sized> RedactedKeyedMap<'a, M, K, V> {
    /// Creates a lazy recursive keyed map view without traversing the map.
    ///
    /// # Parameters
    ///
    /// * `map` - Map-like container to borrow.
    /// * `policy` - Complete policy snapshot owned by the map view.
    ///
    /// # Returns
    ///
    /// A lazy borrowed map view that shares its policy across all entries.
    #[must_use = "format the recursive keyed redaction view"]
    #[inline(always)]
    pub const fn new(map: &'a M, policy: RedactionPolicy) -> Self {
        Self {
            map,
            policy,
            marker: PhantomData,
        }
    }

    /// Converts this view into a byte-bounded, log-safe display adapter.
    ///
    /// # Parameters
    ///
    /// * `limit` - Maximum rendered bytes including any truncation marker.
    ///
    /// # Returns
    ///
    /// A display-only adapter that owns this recursive keyed map view.
    #[must_use = "format the bounded recursive keyed map display adapter"]
    #[inline(always)]
    pub const fn with_output_limit(self, limit: LogOutputLimit) -> BoundedRedactedDisplay<Self> {
        BoundedRedactedDisplay::new(self, limit)
    }

    /// Converts this view into a byte-bounded display adapter using its policy.
    ///
    /// # Returns
    ///
    /// A display-only adapter bounded by this view's diagnostic output budget.
    #[must_use = "format the bounded recursive keyed map display adapter"]
    #[inline]
    pub fn with_policy_output_limit(self) -> BoundedRedactedDisplay<Self> {
        let limit = LogOutputLimit::from(self.policy.diagnostic_budget());
        BoundedRedactedDisplay::new(self, limit)
    }
}

impl<M: ?Sized, K: AsRef<str> + Debug + ?Sized, V: Redact + RedactValue + ?Sized> Debug
    for RedactedKeyedMap<'_, M, K, V>
where
    for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V)>,
{
    /// Formats each entry through its key-selected redaction behavior.
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
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut output = formatter.debug_map();
        for (key, value) in self.map {
            output.entry(
                &key,
                &RedactedKeyedValue::new(key.as_ref(), value, &self.policy),
            );
        }
        output.finish()
    }
}

impl<M: ?Sized, K: AsRef<str> + Debug + ?Sized, V: Redact + RedactValue + ?Sized> Display
    for RedactedKeyedMap<'_, M, K, V>
where
    for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V)>,
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
        let mut writer = LogEscapeWriter::new(formatter);
        write!(&mut writer, "{self:?}")
    }
}
