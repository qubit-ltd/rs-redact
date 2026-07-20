// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Container implementations for explicit nested redaction.

use std::fmt::{
    self,
    Formatter,
};

#[cfg(feature = "serde")]
use crate::domain::RedactSerialize;
use crate::{
    Redact,
    RedactMut,
    RedactionPolicy,
};

impl<T: Redact> Redact for Option<T> {
    /// Formats `None` directly or a redacted `Some` value with the same policy.
    #[inline]
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        match self {
            Some(value) => formatter
                .debug_tuple("Some")
                .field(&value.redacted_with(policy))
                .finish(),
            None => formatter.write_str("None"),
        }
    }
}

impl<T: Redact + ?Sized> Redact for Box<T> {
    /// Transparently delegates formatting to the boxed object.
    #[inline(always)]
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        self.as_ref().fmt_redacted(policy, formatter)
    }
}

impl<T: Redact> Redact for Vec<T> {
    /// Formats every item through a redacted view sharing the same policy.
    #[inline]
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        let mut list = formatter.debug_list();
        for value in self {
            list.entry(&value.redacted_with(policy));
        }
        list.finish()
    }
}

impl<T: RedactMut> RedactMut for Option<T> {
    /// Redacts a present nested object with the supplied policy.
    #[inline]
    fn redact_in_place_with(&mut self, policy: &RedactionPolicy) {
        if let Some(value) = self {
            value.redact_in_place_with(policy);
        }
    }
}

impl<T: RedactMut + ?Sized> RedactMut for Box<T> {
    /// Transparently delegates mutation to the boxed object.
    #[inline(always)]
    fn redact_in_place_with(&mut self, policy: &RedactionPolicy) {
        self.as_mut().redact_in_place_with(policy);
    }
}

impl<T: RedactMut> RedactMut for Vec<T> {
    /// Redacts every nested item with the supplied policy.
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
    #[inline]
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
    #[inline(always)]
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize_redacted(policy, serializer)
    }
}

#[cfg(feature = "serde")]
impl<T: RedactSerialize> RedactSerialize for Vec<T> {
    /// Serializes every nested item with the same explicit policy.
    #[inline]
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
