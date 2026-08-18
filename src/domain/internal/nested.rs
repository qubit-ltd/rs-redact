// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Container implementations for explicit nested redaction.

#[cfg(feature = "serde")]
use serde::Serializer;

use crate::RedactionPolicy;
use crate::domain::Redact;
use crate::domain::RedactMut;
#[cfg(feature = "serde")]
use crate::domain::RedactSerialize;
use crate::domain::RedactedResult;

impl<T: Redact> Redact for Option<T> {
    /// Formats `None` directly or a redacted `Some` value with the same policy.
    ///
    /// The option first charges its own domain-value node. A present field is
    /// charged before the inner reference is read, then the child enters the
    /// same session through [`RedactedResult`]. Rejected value or field
    /// admission writes one unquoted [`crate::domain::DomainTruncated`] marker.
    /// No diagnostic input bytes are consumed by this domain traversal.
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
    /// Returns [`std::fmt::Error`] when the destination or nested value rejects
    /// a write.
    fn write_redacted(&self, writer: &mut crate::domain::RedactionWriter<'_, '_>) {
        match self {
            None => writer.unit("None"),
            Some(value) => writer.tuple("Some", |fields| {
                let _ = fields.item(|writer| RedactedResult::new(value, writer.session_mut()));
            }),
        }
    }
}

impl<T: Redact + ?Sized> Redact for Box<T> {
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
    /// Returns [`std::fmt::Error`] when the boxed value cannot complete its
    /// output.
    fn write_redacted(&self, writer: &mut crate::domain::RedactionWriter<'_, '_>) {
        self.as_ref().write_redacted(writer)
    }
}

impl<T: Redact> Redact for Vec<T> {
    /// Formats every item through a redacted view sharing the same policy.
    ///
    /// The vector charges its domain-value node once and checks the iterator's
    /// exact remaining length before charging and advancing one item. An
    /// exhausted item budget cannot pull or format another value, while an
    /// exactly full vector does not perform a false terminal admission. Every
    /// child reuses the same session, so node, depth, output, and collection
    /// charges accumulate. Traversal or output exhaustion terminates the list;
    /// a branch-local depth marker leaves later siblings eligible. Domain
    /// traversal never consumes input bytes.
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
    /// Returns [`std::fmt::Error`] when the destination or an item rejects a
    /// write.
    fn write_redacted(&self, writer: &mut crate::domain::RedactionWriter<'_, '_>) {
        writer.list(|fields| {
            for value in self {
                let _ = fields.item(|writer| RedactedResult::new(value, writer.session_mut()));
            }
        });
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
    fn serialize_redacted<S>(&self, policy: &RedactionPolicy, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Some(value) => serializer.serialize_some(&super::RedactedSerialize::new(value, policy)),
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
    fn serialize_redacted<S>(&self, policy: &RedactionPolicy, serializer: S) -> Result<S::Ok, S::Error>
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
    fn serialize_redacted<S>(&self, policy: &RedactionPolicy, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;

        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for value in self {
            sequence.serialize_element(&super::RedactedSerialize::new(value, policy))?;
        }
        sequence.end()
    }
}
