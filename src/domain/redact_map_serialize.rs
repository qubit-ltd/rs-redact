// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Hidden serialization hook for redacted text-valued maps.

use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap;

use crate::RedactValue;
use crate::RedactionPolicy;
use crate::policy::ResolvedField;

/// Serializes map values after classifying them by runtime key.
///
/// # Type Parameters
///
/// * `K` - Runtime map-key type used for field classification.
/// * `V` - Map-value type serialized through redaction.
#[doc(hidden)]
pub trait RedactMapSerialize<K: ?Sized, V: ?Sized> {
    /// Serializes this map through `policy`.
    ///
    /// # Type Parameters
    ///
    /// * `S` - Destination Serde serializer type.
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
        S: Serializer;
}

impl<M: ?Sized, K: ?Sized, V: ?Sized> RedactMapSerialize<K, V> for M
where
    for<'a> &'a M: IntoIterator<Item = (&'a K, &'a V)>,
    K: AsRef<str> + Serialize,
    V: RedactValue + Serialize,
{
    /// Serializes every entry through the map redaction contract.
    ///
    /// # Type Parameters
    ///
    /// * `S` - Destination Serde serializer type.
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
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in self {
            let resolved = policy.resolve_field(key.as_ref());
            match resolved {
                ResolvedField::Sensitive { sensitivity } => {
                    let redacted = value.redact_value(sensitivity, policy.masking());
                    map.serialize_entry(key, &redacted)?;
                }
                ResolvedField::PassThrough => {
                    map.serialize_entry(key, value)?;
                }
            }
        }
        map.end()
    }
}
