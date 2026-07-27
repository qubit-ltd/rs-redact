// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Hidden serialization hook for redacted text-valued maps.

use serde::{
    Serialize,
    ser::SerializeMap,
};

use crate::{
    RedactValue,
    RedactionPolicy,
};

/// Serializes map values after classifying them by runtime key.
#[doc(hidden)]
pub trait RedactMapSerialize<K: ?Sized, V: ?Sized> {
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

impl<M: ?Sized, K: ?Sized, V: ?Sized> RedactMapSerialize<K, V> for M
where
    for<'a> &'a M: IntoIterator<Item = (&'a K, &'a V)>,
    K: AsRef<str> + Serialize,
    V: RedactValue + Serialize,
{
    /// Serializes every entry through the map redaction contract.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy used to classify every runtime key.
    /// * `serializer` - Destination Serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's successful map output.
    ///
    /// # Errors
    ///
    /// Returns the first entry or destination serialization error unchanged.
    #[inline]
    fn serialize_redacted_map<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in self {
            if let Some(level) = policy.sensitivity_for(key.as_ref()) {
                let redacted = value.redact_value(level, policy.masking());
                map.serialize_entry(key, &redacted)?;
            } else {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}
