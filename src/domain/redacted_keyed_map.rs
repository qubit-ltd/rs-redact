// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy borrowed view of a map whose values support recursive redaction.

use std::{
    fmt::{
        self,
        Debug,
        Display,
        Formatter,
        Write as _,
    },
    marker::PhantomData,
};

use crate::{
    BoundedRedactedDisplay,
    LogOutputLimit,
    Redact,
    RedactValue,
    RedactionPolicy,
    RedactionSession,
    text::internal::LogEscapeWriter,
};

use super::{
    bounded_redacted_display::format_bounded,
    bounded_redacted_display::format_debug_bounded,
    internal::mask_byte_limit,
};

/// A lazy map view that classifies each value by its key before recursion.
///
/// Unknown and explicitly allowed keys delegate to the corresponding value's
/// [`Redact`] implementation. Sensitive keys mask the complete value through
/// [`RedactValue`].
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed map.
/// * `M` - Borrowed map-like container type.
/// * `K` - Runtime key type used for field classification.
/// * `V` - Value type recursively rendered through redaction.
#[must_use = "format the recursive keyed redaction view"]
pub struct RedactedKeyedMap<
    'a,
    M: ?Sized,
    K: ?Sized = String,
    V: ?Sized = String,
> {
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
    /// A bounded formatting adapter that owns this recursive keyed map view.
    #[must_use = "format the bounded recursive keyed map display adapter"]
    #[inline(always)]
    pub const fn with_output_limit(
        self,
        limit: LogOutputLimit,
    ) -> BoundedRedactedDisplay<Self> {
        BoundedRedactedDisplay::new(self, limit)
    }

    /// Converts this view into a byte-bounded display adapter using its policy.
    ///
    /// # Returns
    ///
    /// A formatting adapter bounded by this view's diagnostic output budget.
    #[must_use = "format the bounded recursive keyed map display adapter"]
    #[inline]
    pub fn with_policy_output_limit(self) -> BoundedRedactedDisplay<Self> {
        let limit =
            LogOutputLimit::from(self.policy.limits().diagnostic_event());
        BoundedRedactedDisplay::new(self, limit)
    }
}

impl<
    M: ?Sized,
    K: AsRef<str> + Debug + ?Sized,
    V: Redact + RedactValue + ?Sized,
> Debug for RedactedKeyedMap<'_, M, K, V>
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
        let session = RedactionSession::diagnostic(&self.policy);
        let view = RedactedKeyedMapSession::new(self.map, &session);
        if mask_byte_limit().is_some() {
            return Debug::fmt(&view, formatter);
        }
        format_debug_bounded(
            &view,
            LogOutputLimit::from(self.policy.limits().diagnostic_event()),
            formatter,
        )
    }
}

mod session_view {
    use std::{
        fmt::{
            self,
            Debug,
            Formatter,
        },
        marker::PhantomData,
    };

    use crate::{
        Redact,
        RedactValue,
        RedactedKeyedValueSession,
        RedactionSession,
    };

    /// A nested keyed-map view that reuses an existing diagnostic session.
    #[must_use = "format the nested keyed redaction view"]
    pub struct RedactedKeyedMapSession<
        'map,
        'session,
        'policy,
        M: ?Sized,
        K: ?Sized = String,
        V: ?Sized = String,
    > {
        map: &'map M,
        session: &'session RedactionSession<'policy>,
        marker: PhantomData<fn() -> (*const K, *const V)>,
    }

    impl<'map, 'session, 'policy, M: ?Sized, K: ?Sized, V: ?Sized>
        RedactedKeyedMapSession<'map, 'session, 'policy, M, K, V>
    {
        /// Creates a nested keyed-map view using an existing diagnostic
        /// session.
        #[inline(always)]
        pub fn new(
            map: &'map M,
            session: &'session RedactionSession<'policy>,
        ) -> Self {
            Self {
                map,
                session,
                marker: PhantomData,
            }
        }
    }

    impl<
        M: ?Sized,
        K: AsRef<str> + Debug + ?Sized,
        V: Redact + RedactValue + ?Sized,
    > Debug for RedactedKeyedMapSession<'_, '_, '_, M, K, V>
    where
        for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V)>,
    {
        /// Formats each entry through the existing keyed diagnostic session.
        #[inline]
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            let mut output = formatter.debug_map();
            for (key, value) in self.map {
                output.entry(
                    &key,
                    &RedactedKeyedValueSession::new(
                        key.as_ref(),
                        value,
                        self.session,
                    ),
                );
            }
            output.finish()
        }
    }
}

pub use session_view::RedactedKeyedMapSession;

impl<
    M: ?Sized,
    K: AsRef<str> + Debug + ?Sized,
    V: Redact + RedactValue + ?Sized,
> Display for RedactedKeyedMapSession<'_, '_, '_, M, K, V>
where
    for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V)>,
{
    /// Escapes nested keyed-map debug output for plain-text logs.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = LogEscapeWriter::new(formatter);
        write!(&mut writer, "{self:?}")
    }
}

impl<
    M: ?Sized,
    K: AsRef<str> + Debug + ?Sized,
    V: Redact + RedactValue + ?Sized,
> Display for RedactedKeyedMap<'_, M, K, V>
where
    for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V)>,
{
    /// Formats bounded compact redacted debug output and escapes it for
    /// plain-text logs.
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
        let session = RedactionSession::diagnostic(&self.policy);
        let view = RedactedKeyedMapSession::new(self.map, &session);
        format_bounded(
            &view,
            LogOutputLimit::from(self.policy.limits().diagnostic_event()),
            formatter,
        )
    }
}
