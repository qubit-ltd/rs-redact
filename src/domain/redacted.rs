// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed, policy-snapshot view of a domain object.

use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use super::bounded_redacted_display::format_bounded;
use crate::LogOutputLimit;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::domain::BoundedRedactedDisplay;
use crate::domain::Redact;

/// Completion state used by containers to decide whether siblings may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainRenderStatus {
    Complete,
    DepthTruncated,
    TraversalTruncated,
    OutputTruncated,
}

impl DomainRenderStatus {
    /// Returns whether shared traversal or output exhaustion stops siblings.
    pub(crate) const fn stops_siblings(self) -> bool {
        matches!(self, Self::TraversalTruncated | Self::OutputTruncated)
    }
}

/// A lazy non-destructive redacted view of a domain object.
///
/// The view borrows the original object and owns a cheap clone of the complete
/// policy. Creating it does not inspect, clone, or modify object fields.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed domain object.
/// * `T` - Domain-object type rendered or serialized through redaction.
#[must_use = "format or serialize the redacted view"]
pub struct Redacted<'a, T: ?Sized> {
    /// Domain object rendered through this view.
    value: &'a T,
    /// Immutable policy snapshot used for every formatting operation.
    policy: RedactionPolicy,
}

impl<'a, T: ?Sized> Redacted<'a, T> {
    /// Creates a redacted view from a borrowed object and an owned policy.
    ///
    /// # Parameters
    ///
    /// * `value` - Domain object to borrow without inspecting its fields.
    /// * `policy` - Complete policy snapshot owned by the view.
    ///
    /// # Returns
    ///
    /// A lazy redacted view.
    #[inline(always)]
    pub(crate) const fn new(value: &'a T, policy: RedactionPolicy) -> Self {
        Self { value, policy }
    }

    /// Converts this view into a byte-bounded, log-safe display adapter.
    ///
    /// # Parameters
    ///
    /// * `limit` - Maximum rendered bytes including any truncation marker.
    ///
    /// # Returns
    ///
    /// A bounded formatting adapter that owns this redacted view.
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
    #[must_use = "format the bounded redacted display adapter"]
    #[inline]
    pub fn with_policy_output_limit(self) -> BoundedRedactedDisplay<Self> {
        let limit =
            LogOutputLimit::from(self.policy.limits().diagnostic_event());
        BoundedRedactedDisplay::new(self, limit)
    }

    /// Returns the borrowed domain value to crate-internal adapters.
    ///
    /// # Returns
    ///
    /// The original domain value borrowed for the view's lifetime.
    #[cfg(feature = "serde")]
    #[inline(always)]
    pub(crate) const fn value(&self) -> &'a T {
        self.value
    }

    /// Returns the policy snapshot to crate-internal adapters.
    ///
    /// # Returns
    ///
    /// The immutable policy snapshot owned by this view.
    #[cfg(feature = "serde")]
    #[inline(always)]
    pub(crate) const fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }
}

#[cfg(feature = "serde")]
impl<T: crate::domain::RedactSerialize + ?Sized> serde::Serialize
    for Redacted<'_, T>
{
    /// Delegates serialization to the derived redaction hook.
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
    /// The derived hook's successful output.
    ///
    /// # Errors
    ///
    /// Returns the derived hook's serialization error unchanged.
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value().serialize_redacted(self.policy(), serializer)
    }
}

impl<T: Redact + ?Sized> Debug for Redacted<'_, T> {
    /// Writes the object's redacted representation while preserving formatter
    /// flags such as alternate pretty formatting.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context whose flags are passed to
    ///   the object's redaction hook.
    ///
    /// # Returns
    ///
    /// The formatter result for the complete redacted representation.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the object cannot write its complete
    /// redacted representation.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut session = RedactionSession::new(&self.policy);
        let view = RedactedResult::new_with_alternate(
            self.value,
            &mut session,
            formatter.alternate(),
        );
        Debug::fmt(&view, formatter)
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
    use crate::domain::Redact;
    use crate::domain::internal::mark_debug_output_exhausted;
    use crate::domain::internal::mask_byte_limit;
    use crate::domain::internal::with_debug_output_tracking;
    use crate::domain::internal::with_mask_byte_limit;
    use crate::policy::DomainTruncation;
    use crate::policy::FragmentCompletion;
    use crate::policy::RedactionAdmission;
    use crate::text::internal::LogEscapeWriter;

    /// An eagerly completed nested redacted representation.
    #[must_use = "format the nested redacted view"]
    pub struct RedactedResult<'value, T: ?Sized> {
        completed: CompletedDebug,
        status: super::DomainRenderStatus,
        marker: PhantomData<&'value T>,
    }

    impl<'value, T: Redact + ?Sized> RedactedResult<'value, T> {
        /// Completes a compact nested representation through `session`.
        #[inline(always)]
        pub fn new(
            value: &'value T,
            session: &mut RedactionSession<'_>,
        ) -> Self {
            Self::try_new_with_alternate(value, session, false)
                .unwrap_or_else(Self::empty)
        }

        /// Attempts to complete one nested item, rejecting exhausted sessions.
        pub(crate) fn try_new(
            value: &'value T,
            session: &mut RedactionSession<'_>,
            alternate: bool,
        ) -> Option<Self> {
            Self::try_new_with_alternate(value, session, alternate)
        }

        /// Returns whether this result exhausted shared sibling eligibility.
        pub(crate) fn stops_siblings(&self) -> bool {
            self.status.stops_siblings()
        }

        /// Completes a nested representation while preserving pretty debug.
        pub(crate) fn new_with_alternate(
            value: &'value T,
            session: &mut RedactionSession<'_>,
            alternate: bool,
        ) -> Self {
            Self::try_new_with_alternate(value, session, alternate)
                .unwrap_or_else(Self::empty)
        }

        /// Completes one domain value with output-only admission.
        ///
        /// Pure domain rendering deliberately does not reserve or consume
        /// diagnostic input bytes. The output frame exists solely to cap the
        /// owned completion and to let [`RedactionSession::commit_output`]
        /// subtract only bytes not already committed by nested results. A
        /// domain-generation checkpoint distinguishes structural admission
        /// failure from byte truncation: structural truncation leaves the
        /// session output open for eligible siblings, whereas exhausting the
        /// shared output ceiling closes it. `None` means no output byte remains
        /// and the value must not be accessed.
        fn try_new_with_alternate(
            value: &'value T,
            session: &mut RedactionSession<'_>,
            alternate: bool,
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
                let wrapper = RedactOnce {
                    value,
                    session: RefCell::new(Some(session)),
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
                super::DomainRenderStatus::OutputTruncated
            } else {
                match domain_truncation {
                    DomainTruncation::None => {
                        super::DomainRenderStatus::Complete
                    }
                    DomainTruncation::Depth => {
                        super::DomainRenderStatus::DepthTruncated
                    }
                    DomainTruncation::Traversal => {
                        super::DomainRenderStatus::TraversalTruncated
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

        /// Creates a valid empty result after complete output exhaustion.
        pub(crate) fn empty() -> Self {
            Self {
                completed: CompletedDebug::empty(),
                status: super::DomainRenderStatus::Complete,
                marker: PhantomData,
            }
        }
    }

    impl<T: ?Sized> Debug for RedactedResult<'_, T> {
        /// Writes the already-completed safe representation.
        #[inline(always)]
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            Debug::fmt(&self.completed, formatter)
        }
    }

    impl<T: ?Sized> Display for RedactedResult<'_, T> {
        /// Escapes the nested redacted representation for plain-text logs.
        #[inline(always)]
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            let mut writer = LogEscapeWriter::new(formatter);
            write!(&mut writer, "{self:?}")
        }
    }

    /// One-shot debug adapter consumed while completing a safe result.
    struct RedactOnce<'value, 'session, 'policy, T: ?Sized> {
        value: &'value T,
        session: RefCell<Option<&'session mut RedactionSession<'policy>>>,
    }

    impl<T: Redact + ?Sized> Debug for RedactOnce<'_, '_, '_, T> {
        /// Invokes the mutable redaction hook exactly once.
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            let mut session = self.session.borrow_mut();
            let session = session
                .take()
                .expect("the one-shot redaction adapter cannot be reused");
            self.value.fmt_redacted(session, formatter)
        }
    }

    /// Owned, bounded debug result that retains a formatter failure.
    pub(crate) struct CompletedDebug {
        output: String,
        valid: bool,
        truncated: bool,
    }

    impl CompletedDebug {
        /// Creates a valid result with no rendered bytes.
        pub(crate) fn empty() -> Self {
            Self {
                output: String::new(),
                valid: true,
                truncated: false,
            }
        }

        /// Returns the exact number of completed UTF-8 output bytes.
        pub(crate) fn len(&self) -> usize {
            self.output.len()
        }

        /// Returns whether the byte ceiling replaced output with a marker.
        pub(crate) fn truncated(&self) -> bool {
            self.truncated
        }
    }

    impl Debug for CompletedDebug {
        /// Writes the completed debug output when it is valid.
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            if self.valid {
                formatter.write_str(&self.output)
            } else {
                Err(fmt::Error)
            }
        }
    }

    /// Completes a debug value into a bounded owned representation.
    ///
    /// The formatter writes at most `limit` UTF-8 bytes, preserving complete
    /// debug escape sequences. If the value crosses the ceiling, the longest
    /// safe prefix that leaves room for the complete unquoted `<truncated>`
    /// marker is retained. A limit smaller than the marker yields empty output.
    /// Alternate formatting is forwarded exactly once. This function bounds
    /// the destination buffer, but it cannot bound computation or allocation
    /// performed internally by an arbitrary user `Debug` implementation.
    pub(crate) fn complete_debug(
        value: &dyn Debug,
        limit: usize,
        alternate: bool,
    ) -> CompletedDebug {
        let mut writer = CompletedDebugWriter::new(limit);
        let result = with_mask_byte_limit(limit, || {
            with_debug_output_tracking(|| {
                if alternate {
                    write!(&mut writer, "{value:#?}")
                } else {
                    write!(&mut writer, "{value:?}")
                }
            })
        });
        let truncated = writer.truncated;
        CompletedDebug {
            output: writer.finish(),
            valid: result.is_ok() || truncated,
            truncated,
        }
    }

    /// Bounded buffer used only while completing an eager safe result.
    struct CompletedDebugWriter {
        output: String,
        limit: usize,
        truncated: bool,
    }

    impl CompletedDebugWriter {
        /// Creates an empty bounded completion buffer.
        fn new(limit: usize) -> Self {
            Self {
                output: String::with_capacity(limit),
                limit,
                truncated: false,
            }
        }

        /// Finishes the buffer with a complete terminal marker when needed.
        fn finish(mut self) -> String {
            if self.truncated {
                let marker = "<truncated>";
                if self.limit < marker.len() {
                    return String::new();
                }
                let prefix_limit = self.limit.saturating_sub(marker.len());
                let end = debug_piece_boundary(&self.output, prefix_limit);
                self.output.truncate(end);
                self.output.push_str(marker);
            }
            self.output
        }
    }

    impl fmt::Write for CompletedDebugWriter {
        /// Retains complete UTF-8 fragments until the configured limit closes.
        fn write_str(&mut self, value: &str) -> fmt::Result {
            if self.truncated {
                return Err(fmt::Error);
            }
            if self.output.len().saturating_add(value.len()) <= self.limit {
                self.output.push_str(value);
                return Ok(());
            }
            let payload_limit = self.limit.saturating_sub("<truncated>".len());
            let remaining = payload_limit.saturating_sub(self.output.len());
            let end = debug_piece_boundary(value, remaining);
            self.output.push_str(&value[..end]);
            self.truncated = true;
            mark_debug_output_exhausted();
            Err(fmt::Error)
        }
    }

    /// Returns the longest prefix that preserves UTF-8 and debug escapes.
    fn debug_piece_boundary(value: &str, limit: usize) -> usize {
        let mut offset = 0;
        while offset < value.len() {
            let remaining = &value[offset..];
            let piece_len = debug_escape_len(remaining).unwrap_or_else(|| {
                remaining.chars().next().map_or(0, char::len_utf8)
            });
            if offset.saturating_add(piece_len) > limit {
                break;
            }
            offset += piece_len;
        }
        offset
    }

    /// Returns one complete Rust debug escape length at the string start.
    fn debug_escape_len(value: &str) -> Option<usize> {
        let bytes = value.as_bytes();
        if bytes.first() != Some(&b'\\') {
            return None;
        }
        match bytes.get(1).copied()? {
            b'\\' | b'"' | b'n' | b'r' | b't' | b'0' => Some(2),
            b'x' if bytes.len() >= 4
                && bytes[2].is_ascii_hexdigit()
                && bytes[3].is_ascii_hexdigit() =>
            {
                Some(4)
            }
            b'u' if bytes.get(2) == Some(&b'{') => {
                let closing = bytes[3..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|index| index + 3)?;
                if closing == 3
                    || !bytes[3..closing].iter().all(u8::is_ascii_hexdigit)
                {
                    return None;
                }
                Some(closing + 1)
            }
            _ => None,
        }
    }
}

pub(crate) use session_view::CompletedDebug;
pub use session_view::RedactedResult;
pub(crate) use session_view::complete_debug;

impl<T: Redact + ?Sized> Display for Redacted<'_, T> {
    /// Writes a bounded compact redacted debug representation escaped for logs.
    ///
    /// Redacted debug output is escaped directly into the destination without
    /// constructing an intermediate [`String`]. This implementation never
    /// calls the original object's `Display`.
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
    /// Returns [`fmt::Error`] when the destination cannot accept the complete
    /// log-safe representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut session = RedactionSession::new(&self.policy);
        let view = RedactedResult::new(self.value, &mut session);
        format_bounded(
            &view,
            LogOutputLimit::from(self.policy.limits().diagnostic_event()),
            formatter,
        )
    }
}
