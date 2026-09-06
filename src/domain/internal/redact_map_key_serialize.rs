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
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::admit_input;
use super::redact_serialize_scope::remaining_output_bytes;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Internal structured serialization capability for sensitive map keys.
#[doc(hidden)]
pub trait RedactMapKeySerialize {
    /// Serializes masked keys and rejects collisions introduced by masking.
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

macro_rules! map_key_serialize {
    ($map:ty) => {
        impl<K, V> RedactMapKeySerialize for $map
        where
            K: AsRef<str>,
            V: Serialize + RedactLevelSerialize,
        {
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
                            let (masked, truncated) =
                                policy
                                    .masking()
                                    .mask_bounded_with_truncation(key_level, raw, remaining_output_bytes());
                            if truncated {
                                return Err(S::Error::custom("redaction map key output budget exceeded"));
                            }
                            masked
                        }
                    };
                    if key.len() > remaining_output_bytes() {
                        return Err(S::Error::custom("redaction map key output budget exceeded"));
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

/// Already transformed key whose source bytes were admitted before masking.
struct KeyPayload<'a>(&'a str);

impl Serialize for KeyPayload<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !super::redact_serialize_scope::admit_node() {
            return Err(S::Error::custom("redaction map key structural budget exceeded"));
        }
        let _node = super::serde_node_guard::SerdeNodeGuard;
        super::redact_serialize_scope::serialize_payload(serializer, self.0)
    }
}
