// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy borrowed view of a string-valued map-like container.

use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::marker::PhantomData;

use super::internal::mask_byte_limit;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::domain::RedactMapValue;

/// A lazy map view that classifies values by their runtime keys.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed map.
/// * `M` - Borrowed map-like container type. The blanket [`RedactMapValue`]
///   implementation requires its iterator to implement [`ExactSizeIterator`].
/// * `K` - Runtime key type used for field classification.
/// * `V` - Value type formatted or serialized through redaction.
///
/// # Iterator Contract
///
/// A borrowed map whose iterator is not exact cannot use the blanket map
/// redaction implementation:
///
/// ```compile_fail
/// use std::slice;
///
/// use qubit_redact::domain::RedactedMap;
/// use qubit_redact::RedactionPolicy;
///
/// struct InexactMap(Vec<(String, String)>);
///
/// struct InexactIter<'a>(slice::Iter<'a, (String, String)>);
///
/// impl<'a> Iterator for InexactIter<'a> {
///     type Item = (&'a String, &'a String);
///
///     fn next(&mut self) -> Option<Self::Item> {
///         self.0.next().map(|(key, value)| (key, value))
///     }
/// }
///
/// impl<'a> IntoIterator for &'a InexactMap {
///     type Item = (&'a String, &'a String);
///     type IntoIter = InexactIter<'a>;
///
///     fn into_iter(self) -> Self::IntoIter {
///         InexactIter(self.0.iter())
///     }
/// }
///
/// let map = InexactMap(vec![]);
/// let view: RedactedMap<'_, InexactMap, String, String> =
///     RedactedMap::new(&map, RedactionPolicy::default());
/// let _ = format!("{view:?}");
/// ```
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
    #[must_use]
    #[inline(always)]
    pub const fn new(map: &'a M, policy: RedactionPolicy) -> Self {
        Self {
            map,
            policy,
            marker: PhantomData,
        }
    }
}

impl<M: RedactMapValue<K, V> + ?Sized, K: ?Sized, V: ?Sized> Debug for RedactedMap<'_, M, K, V> {
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
        let mut session = RedactionSession::new(&self.policy);
        let view = RedactedMapResult::new_with_alternate(self.map, &mut session, formatter.alternate());
        if mask_byte_limit().is_some() {
            return Debug::fmt(&view, formatter);
        }
        super::internal::format_log_safe(&view, formatter)
    }
}

mod session_view {
    use std::cell::RefCell;
    use std::fmt;
    use std::fmt::Debug;
    use std::fmt::Display;
    use std::fmt::Formatter;
    use std::fmt::Write as _;
    use std::marker::PhantomData;

    use crate::RedactionSession;
    use crate::domain::RedactMapValue;
    use crate::domain::internal::mask_byte_limit;
    use crate::domain::redacted::CompletedDebug;
    use crate::domain::redacted::complete_debug;
    use crate::output::internal::LogEscapeWriter;
    use crate::policy::DomainTruncation;

    /// A nested map view that reuses one diagnostic session.
    pub struct RedactedMapResult<'map, M: ?Sized, K: ?Sized = String, V: ?Sized = String> {
        completed: CompletedDebug,
        marker: PhantomData<(&'map M, *const K, *const V)>,
    }

    impl<'map, M: RedactMapValue<K, V> + ?Sized, K: ?Sized, V: ?Sized> RedactedMapResult<'map, M, K, V> {
        /// Completes a nested map through an existing diagnostic session.
        #[must_use]
        #[inline(always)]
        pub fn new(map: &'map M, session: &mut RedactionSession<'_>) -> Self {
            Self::new_with_alternate(map, session, false)
        }

        /// Completes a nested map while preserving alternate debug.
        ///
        /// Map rendering consumes no diagnostic input bytes. The output-only
        /// frame bounds the whole structure and ensures nested commits are
        /// deducted exactly once. Structural budget rejection is recorded as
        /// domain truncation without closing output needed by eligible sibling
        /// fields; reaching the shared byte ceiling closes session output.
        #[must_use]
        pub(crate) fn new_with_alternate(map: &'map M, session: &mut RedactionSession<'_>, alternate: bool) -> Self {
            let domain_limit = mask_byte_limit().unwrap_or(usize::MAX);
            let max_output_bytes = usize::MAX;
            let checkpoint = session.domain_truncation_checkpoint();
            let completed = {
                let wrapper = MapOnce {
                    map,
                    session: RefCell::new(Some(session)),
                    marker: PhantomData,
                };
                complete_debug(&wrapper, max_output_bytes, alternate)
            };
            let domain_truncated = session.domain_truncation_since(checkpoint) != DomainTruncation::None;
            let _ = (completed.truncated(), domain_limit, domain_truncated);
            Self {
                completed,
                marker: PhantomData,
            }
        }
    }

    impl<M: ?Sized, K: ?Sized, V: ?Sized> Debug for RedactedMapResult<'_, M, K, V> {
        /// Writes the already-completed safe map representation.
        #[inline(always)]
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            Debug::fmt(&self.completed, formatter)
        }
    }

    impl<M: ?Sized, K: ?Sized, V: ?Sized> Display for RedactedMapResult<'_, M, K, V> {
        /// Escapes the nested map representation for plain-text logs.
        #[inline(always)]
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            let mut writer = LogEscapeWriter::new(formatter);
            write!(&mut writer, "{self:?}")
        }
    }

    /// One-shot adapter used to complete a map before returning its view.
    struct MapOnce<'map, 'session, 'policy, M: ?Sized, K: ?Sized, V: ?Sized> {
        map: &'map M,
        session: RefCell<Option<&'session mut RedactionSession<'policy>>>,
        marker: PhantomData<fn() -> (*const K, *const V)>,
    }

    impl<M: RedactMapValue<K, V> + ?Sized, K: ?Sized, V: ?Sized> Debug for MapOnce<'_, '_, '_, M, K, V> {
        /// Invokes map redaction exactly once while constructing owned output.
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            let mut session = self.session.borrow_mut();
            let session = session.take().expect("the one-shot map adapter cannot be reused");
            self.map.write_redacted_map(session, formatter)
        }
    }
}

pub use session_view::RedactedMapResult;

impl<M: RedactMapValue<K, V> + ?Sized, K: ?Sized, V: ?Sized> Display for RedactedMap<'_, M, K, V> {
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
        let view = RedactedMapResult::new(self.map, &mut session);
        Debug::fmt(&view, formatter)
    }
}

#[cfg(feature = "serde")]
impl<M: crate::domain::RedactMapSerialize<K, V> + ?Sized, K: ?Sized, V: ?Sized> serde::Serialize
    for RedactedMap<'_, M, K, V>
{
    /// Serializes values after classifying each one by its runtime key.
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
