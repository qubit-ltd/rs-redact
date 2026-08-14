// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy borrowed view of a map whose values support recursive redaction.

use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Write as _;
use std::marker::PhantomData;

use super::bounded_redacted_display::format_bounded;
use super::internal::mask_byte_limit;
use crate::BoundedRedactedDisplay;
use crate::LogOutputLimit;
use crate::Redact;
use crate::RedactValue;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::text::internal::LogEscapeWriter;

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
        let mut session = RedactionSession::new(&self.policy);
        let view = RedactedKeyedMapResult::new_with_alternate(
            self.map,
            &mut session,
            formatter.alternate(),
        );
        if mask_byte_limit().is_some() {
            return Debug::fmt(&view, formatter);
        }
        Debug::fmt(&view, formatter)
    }
}

mod session_view {
    use std::cell::RefCell;
    use std::fmt;
    use std::fmt::Debug;
    use std::fmt::Formatter;
    use std::marker::PhantomData;

    use crate::Redact;
    use crate::RedactValue;
    use crate::RedactedKeyedResult;
    use crate::RedactionSession;
    use crate::domain::internal::debug_output_exhausted;
    use crate::domain::internal::mask_byte_limit;
    use crate::domain::redacted::CompletedDebug;
    use crate::domain::redacted::complete_debug;

    /// A nested keyed-map view that reuses an existing diagnostic session.
    #[must_use = "format the nested keyed redaction view"]
    pub struct RedactedKeyedMapResult<
        'map,
        M: ?Sized,
        K: ?Sized = String,
        V: ?Sized = String,
    > {
        completed: CompletedDebug,
        marker: PhantomData<(&'map M, *const K, *const V)>,
    }

    impl<
        'map,
        M: ?Sized,
        K: AsRef<str> + Debug + ?Sized,
        V: Redact + RedactValue + ?Sized,
    > RedactedKeyedMapResult<'map, M, K, V>
    where
        for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V)>,
    {
        /// Completes a nested keyed map through an existing session.
        #[inline(always)]
        pub fn new(map: &'map M, session: &mut RedactionSession<'_>) -> Self {
            Self::new_with_alternate(map, session, false)
        }

        /// Completes a nested keyed map while preserving alternate debug.
        pub(crate) fn new_with_alternate(
            map: &'map M,
            session: &mut RedactionSession<'_>,
            alternate: bool,
        ) -> Self {
            let limit = mask_byte_limit()
                .unwrap_or(usize::MAX)
                .min(session.remaining_output_bytes());
            let wrapper = KeyedMapOnce {
                map,
                session: RefCell::new(Some(session)),
                marker: PhantomData,
            };
            let completed = complete_debug(&wrapper, limit, alternate);
            Self {
                completed,
                marker: PhantomData,
            }
        }
    }

    impl<
        M: ?Sized,
        K: AsRef<str> + Debug + ?Sized,
        V: Redact + RedactValue + ?Sized,
    > Debug for RedactedKeyedMapResult<'_, M, K, V>
    {
        /// Writes the already-completed safe keyed-map representation.
        #[inline]
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            Debug::fmt(&self.completed, formatter)
        }
    }

    /// One-shot adapter used to complete a keyed map.
    struct KeyedMapOnce<
        'map,
        'session,
        'policy,
        M: ?Sized,
        K: ?Sized,
        V: ?Sized,
    > {
        map: &'map M,
        session: RefCell<Option<&'session mut RedactionSession<'policy>>>,
        marker: PhantomData<fn() -> (*const K, *const V)>,
    }

    impl<
        M: ?Sized,
        K: AsRef<str> + Debug + ?Sized,
        V: Redact + RedactValue + ?Sized,
    > Debug for KeyedMapOnce<'_, '_, '_, M, K, V>
    where
        for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V)>,
    {
        /// Applies keyed redaction to every entry exactly once.
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            let mut session_slot = self.session.borrow_mut();
            let session = session_slot
                .take()
                .expect("the one-shot keyed-map adapter cannot be reused");
            let alternate = formatter.alternate();
            let mut output = formatter.debug_map();
            let mut entries = self.map.into_iter();
            loop {
                if session.is_exhausted() || debug_output_exhausted() {
                    break;
                }
                let Some((key, value)) = entries.next() else {
                    break;
                };
                let Some(view) = RedactedKeyedResult::try_new(
                    key.as_ref(),
                    value,
                    session,
                    alternate,
                ) else {
                    break;
                };
                let truncated = view.is_truncated();
                output.entry(&key, &view);
                if truncated
                    || session.is_exhausted()
                    || debug_output_exhausted()
                {
                    break;
                }
            }
            output.finish()
        }
    }
}

pub use session_view::RedactedKeyedMapResult;

impl<
    M: ?Sized,
    K: AsRef<str> + Debug + ?Sized,
    V: Redact + RedactValue + ?Sized,
> Display for RedactedKeyedMapResult<'_, M, K, V>
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
        let mut session = RedactionSession::new(&self.policy);
        let view = RedactedKeyedMapResult::new(self.map, &mut session);
        format_bounded(
            &view,
            LogOutputLimit::from(self.policy.limits().diagnostic_event()),
            formatter,
        )
    }
}
