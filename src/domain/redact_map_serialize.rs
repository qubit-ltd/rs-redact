// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Hidden serialization hook for redacted string-valued maps.

use crate::{
    RedactionPolicy,
    Redactor,
};

/// Serializes map values after classifying them by runtime key.
#[doc(hidden)]
pub trait RedactMapSerialize {
    /// Serializes this map through `policy`.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy used to classify every key.
    /// * `serializer` - Destination serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's success value.
    ///
    /// # Errors
    ///
    /// Returns the destination serializer's error unchanged.
    fn serialize_redacted_map<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}

impl<M: ?Sized> RedactMapSerialize for M
where
    for<'a> &'a M: IntoIterator<Item = (&'a String, &'a String)>,
{
    #[inline]
    fn serialize_redacted_map<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let redactor = Redactor::new(policy.clone());
        serializer.collect_map(self.into_iter().map(|(key, value)| {
            (key, redactor.redact(key, value).into_inner())
        }))
    }
}
