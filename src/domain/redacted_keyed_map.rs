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
use crate::LogOutputLimit;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::domain::BoundedRedactedDisplay;
use crate::domain::Redact;
use crate::domain::RedactValue;
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
/// * `M` - Borrowed map-like container whose iterator has an exact length.
/// * `K` - Runtime key type used for field classification.
/// * `V` - Value type recursively rendered through redaction.
///
/// # Iterator Contract
///
/// A borrowed map whose iterator is not exact cannot be formatted as a keyed
/// map:
///
/// ```compile_fail
/// use std::fmt;
/// use std::slice;
///
/// use qubit_redact::{
///     MaskingPolicy, Redact, RedactValue, RedactedKeyedMap,
///     RedactionPolicy, RedactionSession, Sensitivity,
/// };
///
/// #[derive(Debug)]
/// struct Value;
///
/// impl Redact for Value {
///     fn fmt_redacted(
///         &self,
///         _session: &mut RedactionSession<'_>,
///         formatter: &mut fmt::Formatter<'_>,
///     ) -> fmt::Result {
///         formatter.write_str("value")
///     }
/// }
///
/// impl RedactValue for Value {
///     fn redact_value<'a>(
///         &'a self,
///         _level: Sensitivity,
///         _masking: &MaskingPolicy,
///     ) -> qubit_redact::domain::RedactedValue<'a> {
///         unreachable!()
///     }
/// }
///
/// struct InexactMap(Vec<(String, Value)>);
///
/// struct InexactIter<'a>(slice::Iter<'a, (String, Value)>);
///
/// impl<'a> Iterator for InexactIter<'a> {
///     type Item = (&'a String, &'a Value);
///
///     fn next(&mut self) -> Option<Self::Item> {
///         self.0.next().map(|(key, value)| (key, value))
///     }
/// }
///
/// impl<'a> IntoIterator for &'a InexactMap {
///     type Item = (&'a String, &'a Value);
///     type IntoIter = InexactIter<'a>;
///
///     fn into_iter(self) -> Self::IntoIter {
///         InexactIter(self.0.iter())
///     }
/// }
///
/// let map = InexactMap(vec![]);
/// let view: RedactedKeyedMap<'_, InexactMap, String, Value> =
///     RedactedKeyedMap::new(&map, RedactionPolicy::default());
/// let _ = format!("{view:?}");
/// ```
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
    for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V), IntoIter: ExactSizeIterator>,
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

    use crate::RedactionSession;
    use crate::domain::DomainTruncated;
    use crate::domain::Redact;
    use crate::domain::RedactValue;
    use crate::domain::RedactedKeyedResult;
    use crate::domain::internal::debug_output_exhausted;
    use crate::domain::internal::mask_byte_limit;
    use crate::domain::redacted::CompletedDebug;
    use crate::domain::redacted::complete_debug;
    use crate::policy::DomainTraversalAdmission;
    use crate::policy::DomainTruncation;
    use crate::policy::DomainValueAdmission;
    use crate::policy::FragmentCompletion;
    use crate::policy::RedactionAdmission;

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
        K: AsRef<str> + Debug + ?Sized + 'map,
        V: Redact + RedactValue + ?Sized + 'map,
    > RedactedKeyedMapResult<'map, M, K, V>
    where
        for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V)>,
        <&'map M as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        /// Completes a nested keyed map through an existing session.
        ///
        /// The borrowed map iterator must implement [`ExactSizeIterator`]. Its
        /// exact remaining length proves EOF before collection admission, so
        /// no nonexistent item consumes a shared collection token and no
        /// unadmitted entry is pulled.
        #[inline(always)]
        pub fn new(map: &'map M, session: &mut RedactionSession<'_>) -> Self {
            Self::new_with_alternate(map, session, false)
        }

        /// Completes a nested keyed map while preserving alternate debug.
        ///
        /// Keyed domain maps reserve only bounded output; they do not consume
        /// diagnostic input bytes. The output frame charges exact completed
        /// bytes while subtracting bytes already committed by nested values.
        /// Structural limit markers keep output available to admitted siblings,
        /// while shared output exhaustion closes the diagnostic session.
        pub(crate) fn new_with_alternate(
            map: &'map M,
            session: &mut RedactionSession<'_>,
            alternate: bool,
        ) -> Self {
            if session.is_exhausted() {
                return Self {
                    completed: CompletedDebug::empty(),
                    marker: PhantomData,
                };
            }
            let session_limit = session.remaining_output_bytes();
            let domain_limit = mask_byte_limit().unwrap_or(usize::MAX);
            let admission = session.admit_output_only(domain_limit);
            let max_output_bytes = match admission {
                RedactionAdmission::Render { max_output_bytes } => {
                    max_output_bytes
                }
                RedactionAdmission::Fallback => unreachable!(
                    "output-only domain admission cannot reject input"
                ),
                RedactionAdmission::Exhausted => {
                    return Self {
                        completed: CompletedDebug::empty(),
                        marker: PhantomData,
                    };
                }
            };
            let checkpoint = session.domain_truncation_checkpoint();
            let completed = {
                let wrapper = KeyedMapOnce {
                    map,
                    session: RefCell::new(Some(session)),
                    marker: PhantomData,
                };
                complete_debug(&wrapper, max_output_bytes, alternate)
            };
            let domain_truncated = session.domain_truncation_since(checkpoint)
                != DomainTruncation::None;
            let completion = if completed.truncated() {
                if domain_limit < session_limit {
                    FragmentCompletion::DomainTruncated
                } else {
                    FragmentCompletion::SessionTruncated
                }
            } else if domain_truncated {
                FragmentCompletion::DomainTruncated
            } else {
                FragmentCompletion::Complete
            };
            session.commit_output(completed.len(), completion);
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
        'map,
        M: ?Sized,
        K: AsRef<str> + Debug + ?Sized + 'map,
        V: Redact + RedactValue + ?Sized + 'map,
    > Debug for KeyedMapOnce<'map, '_, '_, M, K, V>
    where
        for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V)>,
        <&'map M as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        /// Applies keyed redaction to every entry exactly once.
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            let mut session_slot = self.session.borrow_mut();
            let session = session_slot
                .take()
                .expect("the one-shot keyed-map adapter cannot be reused");
            let DomainValueAdmission::Entered(mut scope) =
                session.enter_domain_value()
            else {
                return Debug::fmt(&DomainTruncated, formatter);
            };
            let alternate = formatter.alternate();
            let mut output = formatter.debug_map();
            let mut entries = self.map.into_iter();
            loop {
                if scope.session().is_exhausted() || debug_output_exhausted() {
                    break;
                }
                if entries.len() == 0 {
                    break;
                }
                if scope.admit_collection_item()
                    == DomainTraversalAdmission::LimitReached
                {
                    output.entry(&DomainTruncated, &DomainTruncated);
                    break;
                }
                let Some((key, value)) = entries.next() else {
                    break;
                };
                let Some(view) = RedactedKeyedResult::try_new_admitted_item(
                    key.as_ref(),
                    value,
                    scope.session(),
                    alternate,
                ) else {
                    output.entry(&DomainTruncated, &DomainTruncated);
                    break;
                };
                let stops_siblings = view.stops_siblings();
                output.entry(&key, &view);
                if stops_siblings
                    || scope.session().is_exhausted()
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
    for<'entry> &'entry M: IntoIterator<Item = (&'entry K, &'entry V), IntoIter: ExactSizeIterator>,
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
