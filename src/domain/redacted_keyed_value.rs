// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy redaction view selected by an external field key.

use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use super::bounded_redacted_display::format_bounded;
use super::bounded_redacted_display::format_debug_bounded;
use super::internal::mask_byte_limit;
use crate::LogOutputLimit;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::domain::Redact;
use crate::domain::RedactValue;
#[cfg(feature = "serde")]
use crate::policy::ResolvedField;

/// A borrowed value rendered according to a separate field key.
///
/// The key is used only to select a policy rule. The view itself renders or
/// serializes the value, and borrows an immutable policy snapshot.
///
/// # Type Parameters
///
/// * `'value` - Lifetime of the borrowed key and value.
/// * `'policy` - Lifetime of the borrowed policy snapshot.
/// * `T` - Value type rendered or serialized through redaction.
pub struct RedactedKeyedValue<'value, 'policy, T: ?Sized> {
    /// Field name used for policy classification.
    key: &'value str,
    /// Value represented by this view.
    value: &'value T,
    /// Immutable policy snapshot borrowed by every output protocol.
    policy: &'policy RedactionPolicy,
}

impl<'value, 'policy, T: ?Sized> RedactedKeyedValue<'value, 'policy, T> {
    /// Creates a keyed view from borrowed inputs and a borrowed policy
    /// snapshot.
    ///
    /// # Parameters
    ///
    /// * `key` - Field name used only for policy classification.
    /// * `value` - Value to render or serialize lazily.
    /// * `policy` - Complete policy snapshot borrowed by this view.
    ///
    /// # Returns
    ///
    /// A view that never modifies the original value.
    #[must_use]
    #[inline(always)]
    pub const fn new(
        key: &'value str,
        value: &'value T,
        policy: &'policy RedactionPolicy,
    ) -> Self {
        Self { key, value, policy }
    }

    /// Returns the external field key used by this view.
    ///
    /// # Returns
    ///
    /// The unchanged policy lookup key.
    #[must_use]
    #[inline(always)]
    pub const fn key(&self) -> &'value str {
        self.key
    }
}

impl<T: Redact + RedactValue + ?Sized> Debug for RedactedKeyedValue<'_, '_, T> {
    /// Formats the value through its selected field classification.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatter whose flags are preserved.
    ///
    /// # Returns
    ///
    /// The complete redacted debug result.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter cannot accept the
    /// complete representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut session = RedactionSession::new(self.policy);
        let view = RedactedKeyedResult::new_with_alternate(
            self.key,
            self.value,
            &mut session,
            formatter.alternate(),
        );
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
    use std::cell::RefCell;
    use std::fmt;
    use std::fmt::Debug;
    use std::fmt::Display;
    use std::fmt::Formatter;
    use std::fmt::Write as _;
    use std::marker::PhantomData;

    use crate::RedactionSession;
    use crate::domain::DomainTruncated;
    use crate::domain::Redact;
    use crate::domain::RedactValue;
    use crate::domain::internal::mask_byte_limit;
    use crate::domain::redacted::CompletedDebug;
    use crate::domain::redacted::DomainRenderStatus;
    use crate::domain::redacted::complete_debug;
    use crate::policy::DomainTraversalAdmission;
    use crate::policy::DomainTruncation;
    use crate::policy::DomainValueAdmission;
    use crate::policy::FragmentCompletion;
    use crate::policy::RedactionAdmission;
    use crate::policy::ResolvedField;
    use crate::text::internal::LogEscapeWriter;

    /// An eagerly completed keyed value representation.
    pub struct RedactedKeyedResult<'value, T: ?Sized> {
        completed: CompletedDebug,
        status: DomainRenderStatus,
        marker: PhantomData<(&'value str, &'value T)>,
    }

    impl<'value, T: Redact + RedactValue + ?Sized> RedactedKeyedResult<'value, T> {
        /// Completes a keyed value through an existing diagnostic session.
        #[inline(always)]
        #[must_use]
        pub fn new(
            key: &'value str,
            value: &'value T,
            session: &mut RedactionSession<'_>,
        ) -> Self {
            Self::new_with_alternate(key, value, session, false)
        }

        /// Completes a keyed value while preserving alternate debug.
        #[must_use]
        pub(crate) fn new_with_alternate(
            key: &'value str,
            value: &'value T,
            session: &mut RedactionSession<'_>,
            alternate: bool,
        ) -> Self {
            Self::try_new_with_mode(
                key,
                value,
                session,
                alternate,
                KeyedAdmissionMode::Standalone,
            )
            .unwrap_or_else(|| Self {
                completed: CompletedDebug::empty(),
                status: DomainRenderStatus::Complete,
                marker: PhantomData,
            })
        }

        /// Attempts to complete an already-admitted keyed map item.
        ///
        /// The keyed-map caller already charged collection structure, so this
        /// path avoids the standalone root and field charges. Key selection is
        /// pure domain formatting and therefore charges no diagnostic input
        /// bytes. Output-only admission establishes a nested accounting frame
        /// so exact completed bytes are charged once.
        pub(crate) fn try_new_admitted_item(
            key: &'value str,
            value: &'value T,
            session: &mut RedactionSession<'_>,
            alternate: bool,
        ) -> Option<Self> {
            Self::try_new_with_mode(
                key,
                value,
                session,
                alternate,
                KeyedAdmissionMode::CollectionItem,
            )
        }

        /// Completes one keyed value under explicit structural provenance.
        fn try_new_with_mode(
            key: &'value str,
            value: &'value T,
            session: &mut RedactionSession<'_>,
            alternate: bool,
            admission_mode: KeyedAdmissionMode,
        ) -> Option<Self> {
            if session.is_exhausted() {
                return None;
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
                RedactionAdmission::Exhausted => return None,
            };
            let checkpoint = session.domain_truncation_checkpoint();
            let completed = {
                let wrapper = KeyedOnce {
                    key,
                    value,
                    session: RefCell::new(Some(session)),
                    admission_mode,
                };
                complete_debug(&wrapper, max_output_bytes, alternate)
            };
            let domain_truncation = session.domain_truncation_since(checkpoint);
            let completion = if completed.truncated() {
                if domain_limit < session_limit {
                    FragmentCompletion::DomainTruncated
                } else {
                    FragmentCompletion::SessionTruncated
                }
            } else if domain_truncation != DomainTruncation::None {
                FragmentCompletion::DomainTruncated
            } else {
                FragmentCompletion::Complete
            };
            let status = if completed.truncated() {
                DomainRenderStatus::OutputTruncated
            } else {
                match domain_truncation {
                    DomainTruncation::None => DomainRenderStatus::Complete,
                    DomainTruncation::Depth => {
                        DomainRenderStatus::DepthTruncated
                    }
                    DomainTruncation::Traversal => {
                        DomainRenderStatus::TraversalTruncated
                    }
                }
            };
            session.commit_output(completed.len(), completion);
            Some(Self {
                completed,
                status,
                marker: PhantomData,
            })
        }

        /// Returns whether this result exhausted shared sibling eligibility.
        #[must_use]
        pub(crate) fn stops_siblings(&self) -> bool {
            self.status.stops_siblings()
        }
    }

    impl<T: ?Sized> Debug for RedactedKeyedResult<'_, T> {
        /// Writes the already-completed safe keyed representation.
        #[inline]
        #[must_use]
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            Debug::fmt(&self.completed, formatter)
        }
    }

    impl<T: ?Sized> Display for RedactedKeyedResult<'_, T> {
        /// Escapes the selected redacted representation for plain-text logs.
        #[inline]
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            let mut writer = LogEscapeWriter::new(formatter);
            write!(&mut writer, "{self:?}")
        }
    }

    /// One-shot adapter used to complete one keyed value.
    struct KeyedOnce<'value, 'session, 'policy, T: ?Sized> {
        key: &'value str,
        value: &'value T,
        session: RefCell<Option<&'session mut RedactionSession<'policy>>>,
        admission_mode: KeyedAdmissionMode,
    }

    /// Records whether a caller already charged this keyed collection item.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum KeyedAdmissionMode {
        Standalone,
        CollectionItem,
    }

    impl<T: Redact + RedactValue + ?Sized> Debug for KeyedOnce<'_, '_, '_, T> {
        /// Applies the selected keyed redaction exactly once.
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            let mut session = self.session.borrow_mut();
            let session = session
                .take()
                .expect("the one-shot keyed adapter cannot be reused");
            if self.admission_mode == KeyedAdmissionMode::Standalone {
                let DomainValueAdmission::Entered(mut scope) =
                    session.enter_domain_value()
                else {
                    return Debug::fmt(&DomainTruncated, formatter);
                };
                if scope.admit_field() == DomainTraversalAdmission::LimitReached
                {
                    return Debug::fmt(&DomainTruncated, formatter);
                }
                return format_resolved(
                    self.key,
                    self.value,
                    scope.session(),
                    formatter,
                );
            }
            format_resolved(self.key, self.value, session, formatter)
        }
    }

    /// Resolves and renders one structurally admitted keyed value.
    fn format_resolved<T: Redact + RedactValue + ?Sized>(
        key: &str,
        value: &T,
        session: &mut RedactionSession<'_>,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        let policy = session.policy();
        match policy.resolve_field(key) {
            ResolvedField::Sensitive { sensitivity } => Debug::fmt(
                &value.redact_value(sensitivity, policy.masking()),
                formatter,
            ),
            ResolvedField::PassThrough => {
                value.fmt_redacted(session, formatter)
            }
        }
    }
}

pub use session_view::RedactedKeyedResult;

impl<T: Redact + RedactValue + ?Sized> Display
    for RedactedKeyedValue<'_, '_, T>
{
    /// Formats the selected redacted representation for a bounded plain-text
    /// log.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination plain-text log boundary.
    ///
    /// # Returns
    ///
    /// The complete escaped redacted representation.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter cannot accept the
    /// complete escaped representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut session = RedactionSession::new(self.policy);
        let view = RedactedKeyedResult::new(self.key, self.value, &mut session);
        format_bounded(
            &view,
            LogOutputLimit::from(self.policy.limits().diagnostic_event()),
            formatter,
        )
    }
}

#[cfg(feature = "serde")]
impl<T: RedactValue + crate::domain::RedactSerialize + ?Sized> serde::Serialize
    for RedactedKeyedValue<'_, '_, T>
{
    /// Serializes the value through its selected field classification.
    ///
    /// # Type Parameters
    ///
    /// * `S` - Destination Serde serializer type.
    ///
    /// # Parameters
    ///
    /// * `serializer` - Destination serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's successful redacted output.
    ///
    /// # Errors
    ///
    /// Returns the destination serializer's error unchanged.
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let resolved = self.policy.resolve_field(self.key);
        match resolved {
            ResolvedField::Sensitive { sensitivity } => {
                serde::Serialize::serialize(
                    &self
                        .value
                        .redact_value(sensitivity, self.policy.masking()),
                    serializer,
                )
            }
            ResolvedField::PassThrough => {
                crate::domain::RedactSerialize::serialize_redacted(
                    self.value,
                    self.policy,
                    serializer,
                )
            }
        }
    }
}
