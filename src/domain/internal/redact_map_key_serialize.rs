// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured serialization for maps with explicitly sensitive keys.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as _;
use serde::ser::SerializeMap;

use super::RedactLevelSerialize;
use super::RedactedLevelSerializeRef;
use super::budget_serialize::BudgetSerialize;
use super::key_payload::KeyPayload;
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::admit_input;
use super::redact_serialize_scope::remaining_payload_bytes;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Internal structured serialization capability for sensitive map keys.
#[doc(hidden)]
pub trait RedactMapKeySerialize {
    /// Serializes masked keys and rejects collisions introduced by masking.
    ///
    /// `Some(value_level)` applies that explicit level to values; `None`
    /// preserves their ordinary representation under the shared budget.
    ///
    /// # Errors
    ///
    /// Returns key collision, admission, or downstream serialization errors.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the map with admitted,
    ///   collision-free keys.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `key_level`: Explicit sensitivity applied to each map key.
    /// - `value_level`: Some level applies explicit leaf masking; None uses
    ///   ordinary budgeted serialization.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_map_keys<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        key_level: Sensitivity,
        value_level: Option<Sensitivity>,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

/// Generates sensitive-key serialization with payload admission and collision
/// checks.
macro_rules! map_key_serialize {
    ($map:ty) => {
        impl<K, V> RedactMapKeySerialize for $map
        where
            K: AsRef<str>,
            V: Serialize + RedactLevelSerialize,
        {
            /// Masks admitted keys, rejects collisions, and serializes values
            /// under one scope.
            ///
            /// # Errors
            ///
            /// Returns key collision, admission, or downstream serializer
            /// errors.
            ///
            /// # Type Parameters
            ///
            /// - `S`: Downstream serializer defining the success and error types.
            ///
            /// # Parameters
            ///
            /// - `serializer`: Destination receiving the map with admitted,
            ///   collision-free keys.
            /// - `policy`: Immutable policy controlling redaction and resource limits.
            /// - `key_level`: Explicit sensitivity applied to each map key.
            /// - `value_level`: Some level applies explicit leaf masking; None uses
            ///   ordinary budgeted serialization.
            ///
            /// # Returns
            ///
            /// The destination result after all emitted data passes shared
            /// admission.
            fn serialize_redacted_map_keys<S>(
                &self,
                serializer: S,
                policy: &RedactionPolicy,
                key_level: Sensitivity,
                value_level: Option<Sensitivity>,
            ) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if !admit_collection_items(self.len()) {
                    return super::redact_serialize_scope::serialize_payload(
                        serializer,
                        policy.masking().mask_opaque(Sensitivity::Secret).as_ref(),
                    );
                }
                let mut output = serializer.serialize_map(Some(self.len()))?;
                let mut emitted = HashSet::new();
                for (key, value) in self {
                    let key = if !policy.is_disabled() && key_level >= Sensitivity::High {
                        Cow::Borrowed(policy.masking().mask_opaque(key_level))
                    } else {
                        let raw = key.as_ref();
                        if !admit_input(raw.len()) {
                            return Err(S::Error::custom("redaction map key input budget exceeded"));
                        }
                        if policy.is_disabled() {
                            Cow::Borrowed(raw)
                        } else {
                            let (masked, truncated) = policy.masking().mask_bounded_with_truncation(
                                key_level,
                                raw,
                                remaining_payload_bytes(),
                            );
                            if truncated {
                                return Err(S::Error::custom("redaction map key payload budget exceeded"));
                            }
                            masked
                        }
                    };
                    if key.len() > remaining_payload_bytes() {
                        return Err(S::Error::custom("redaction map key payload budget exceeded"));
                    }
                    if !emitted.insert(key.to_string()) {
                        return Err(S::Error::custom("redacted map keys collide"));
                    }
                    if let Some(level) = value_level {
                        output.serialize_entry(
                            &KeyPayload(&key),
                            &RedactedLevelSerializeRef::new(value, policy, level),
                        )?;
                    } else {
                        output.serialize_entry(&KeyPayload(&key), &BudgetSerialize::new(value))?;
                    }
                }
                output.end()
            }
        }
    };
}

map_key_serialize!(HashMap<K, V>);
map_key_serialize!(BTreeMap<K, V>);
