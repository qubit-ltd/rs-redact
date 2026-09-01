// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured serialization for maps classified by their keys.

use std::collections::BTreeMap;
use std::collections::HashMap;

use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap;

use super::redact_level_serialize::RedactLevelSerialize;
use super::redact_serialize_scope::admit_collection_items;
use super::redacted_level_serialize_ref::RedactedLevelSerializeRef;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Internal structured serialization capability for policy-classified maps.
#[doc(hidden)]
pub trait RedactMapSerialize {
    /// Serializes a map after classifying each value by its field key.
    fn serialize_redacted_map<S>(&self, serializer: S, policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

macro_rules! map_redact_serialize {
    ($map:ty) => {
        impl<K, V> RedactMapSerialize for $map
        where
            K: AsRef<str> + Serialize,
            V: RedactLevelSerialize + Serialize,
        {
            fn serialize_redacted_map<S>(&self, serializer: S, policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if !admit_collection_items(self.len()) {
                    return serializer.serialize_str(policy.masking().mask_opaque(Sensitivity::Secret).as_ref());
                }
                let mut map = serializer.serialize_map(Some(self.len()))?;
                for (key, value) in self {
                    let key_name = key.as_ref();
                    if !policy.is_disabled() {
                        if let Some(level) = policy.sensitivity_for(key_name) {
                            map.serialize_entry(key, &RedactedLevelSerializeRef::new(value, policy, level))?;
                            continue;
                        }
                    }
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }

        impl<K, V> RedactMapSerialize for Option<$map>
        where
            K: AsRef<str> + Serialize,
            V: RedactLevelSerialize + Serialize,
        {
            fn serialize_redacted_map<S>(&self, serializer: S, policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                match self {
                    Some(value) => value.serialize_redacted_map(serializer, policy),
                    None => serializer.serialize_none(),
                }
            }
        }
    };
}

map_redact_serialize!(HashMap<K, V>);
map_redact_serialize!(BTreeMap<K, V>);
