// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Container implementations for explicit nested redaction.

use std::fmt;
use std::fmt::Formatter;

#[cfg(feature = "serde")]
use serde::Serializer;

use crate::Redact;
use crate::RedactMut;
use crate::RedactedResult;
use crate::RedactionPolicy;
use crate::RedactionSession;
#[cfg(feature = "serde")]
use crate::domain::RedactSerialize;
use crate::domain::internal::debug_output_exhausted;

impl<T: Redact> Redact for Option<T> {
    fn redaction_input_bytes(&self) -> usize {
        self.as_ref().map_or(1, |value| {
            1_usize.saturating_add(Redact::redaction_input_bytes(value))
        })
    }

    /// Formats `None` directly or a redacted `Some` value with the same policy.
    ///
    /// # Parameters
    ///
    /// * `session` - Shared diagnostic session for a present nested value.
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the preserved option shape.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination or nested value rejects a
    /// write.
    #[inline]
    fn fmt_redacted(
        &self,
        session: &mut RedactionSession<'_>,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        match self {
            Some(value) => formatter
                .debug_tuple("Some")
                .field(&RedactedResult::new(value, session))
                .finish(),
            None => formatter.write_str("None"),
        }
    }
}

impl<T: Redact + ?Sized> Redact for Box<T> {
    #[inline(always)]
    fn redaction_input_bytes(&self) -> usize {
        Redact::redaction_input_bytes(self.as_ref())
    }

    /// Transparently delegates formatting to the boxed object.
    ///
    /// # Parameters
    ///
    /// * `session` - Shared diagnostic session forwarded to the boxed value.
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The boxed value's formatter result.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the boxed value cannot complete its output.
    #[inline(always)]
    fn fmt_redacted(
        &self,
        session: &mut RedactionSession<'_>,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        self.as_ref().fmt_redacted(session, formatter)
    }
}

impl<T: Redact> Redact for Vec<T> {
    fn redaction_input_bytes(&self) -> usize {
        self.iter().fold(0_usize, |bytes, value| {
            bytes.saturating_add(Redact::redaction_input_bytes(value))
        })
    }

    /// Formats every item through a redacted view sharing the same policy.
    ///
    /// # Parameters
    ///
    /// * `session` - Shared diagnostic session used by every item.
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the complete list.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination or an item rejects a write.
    #[inline]
    fn fmt_redacted(
        &self,
        session: &mut RedactionSession<'_>,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        let alternate = formatter.alternate();
        let mut list = formatter.debug_list();
        let mut values = self.iter();
        loop {
            if session.is_exhausted() || debug_output_exhausted() {
                break;
            }
            let Some(value) = values.next() else {
                break;
            };
            let Some(view) = RedactedResult::try_new(value, session, alternate)
            else {
                break;
            };
            let truncated = view.is_truncated();
            list.entry(&view);
            if truncated || session.is_exhausted() || debug_output_exhausted() {
                break;
            }
        }
        list.finish()
    }
}

impl<T: RedactMut> RedactMut for Option<T> {
    /// Redacts a present nested object with the supplied policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy applied when the option is present.
    #[inline]
    fn redact_in_place_with(&mut self, policy: &RedactionPolicy) {
        if let Some(value) = self {
            value.redact_in_place_with(policy);
        }
    }
}

impl<T: RedactMut + ?Sized> RedactMut for Box<T> {
    /// Transparently delegates mutation to the boxed object.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy forwarded to the boxed value.
    #[inline(always)]
    fn redact_in_place_with(&mut self, policy: &RedactionPolicy) {
        self.as_mut().redact_in_place_with(policy);
    }
}

impl<T: RedactMut> RedactMut for Vec<T> {
    /// Redacts every nested item with the supplied policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy applied to every item.
    #[inline]
    fn redact_in_place_with(&mut self, policy: &RedactionPolicy) {
        for value in self {
            value.redact_in_place_with(policy);
        }
    }
}

#[cfg(feature = "serde")]
impl<T: RedactSerialize> RedactSerialize for Option<T> {
    /// Preserves `None` or serializes a present nested value with the same
    /// policy.
    ///
    /// # Type Parameters
    ///
    /// * `S` - Destination Serde serializer type.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy shared with a present nested value.
    /// * `serializer` - Destination Serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's successful output.
    ///
    /// # Errors
    ///
    /// Returns the destination serializer's error unchanged.
    #[inline]
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Some(value) => serializer
                .serialize_some(&super::RedactedSerialize::new(value, policy)),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(feature = "serde")]
impl<T: RedactSerialize + ?Sized> RedactSerialize for Box<T> {
    /// Transparently delegates to the boxed serialization hook.
    ///
    /// # Type Parameters
    ///
    /// * `S` - Destination Serde serializer type.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy forwarded to the boxed value.
    /// * `serializer` - Destination Serde serializer.
    ///
    /// # Returns
    ///
    /// The boxed value's successful serializer output.
    ///
    /// # Errors
    ///
    /// Returns the boxed value's serialization error unchanged.
    #[inline(always)]
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_ref().serialize_redacted(policy, serializer)
    }
}

#[cfg(feature = "serde")]
impl<T: RedactSerialize> RedactSerialize for Vec<T> {
    /// Serializes every nested item with the same explicit policy.
    ///
    /// # Type Parameters
    ///
    /// * `S` - Destination Serde serializer type.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy shared by every item.
    /// * `serializer` - Destination Serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's successful sequence output.
    ///
    /// # Errors
    ///
    /// Returns the first item or destination serialization error unchanged.
    #[inline]
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;

        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for value in self {
            sequence.serialize_element(&super::RedactedSerialize::new(
                value, policy,
            ))?;
        }
        sequence.end()
    }
}
