// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Structured serialization for maps with explicitly sensitive keys.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as _;
use serde::ser::SerializeMap;

use super::RedactLevelSerialize;
use super::RedactedLevelSerializeRef;
use super::redact_serialize_scope::admit_collection_items;
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
                    return serializer.serialize_str(policy.masking().mask_opaque(Sensitivity::Secret).as_ref());
                }
                let mut output = serializer.serialize_map(Some(self.len()))?;
                let mut emitted = HashSet::with_capacity(self.len());
                for (key, value) in self {
                    let key = if policy.is_disabled() {
                        key.as_ref().to_owned()
                    } else {
                        policy.masking().mask(key_level, key.as_ref()).into_owned()
                    };
                    if !emitted.insert(key.clone()) {
                        return Err(S::Error::custom("redacted map keys collide"));
                    }
                    if let Some(level) = value_level {
                        output.serialize_entry(&key, &RedactedLevelSerializeRef::new(value, policy, level))?;
                    } else {
                        output.serialize_entry(&key, value)?;
                    }
                }
                output.end()
            }
        }
    };
}

map_key_serialize!(HashMap<K, V>);
map_key_serialize!(BTreeMap<K, V>);
