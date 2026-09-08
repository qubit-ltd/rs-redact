// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sealed capability for maps whose keys use an explicit sensitivity.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

use super::RedactLevelValue;
use super::RedactionFields;
use crate::Sensitivity;

/// Seals the supported capability set against downstream implementations.
mod private {
    /// Restricts this capability to the supported representations.
    pub trait Sealed {
        // empty
    }
}

/// Capability implemented for supported maps with level-capable keys.
#[doc(hidden)]
pub trait RedactMapKeyValue: private::Sealed {
    /// Writes map keys and optional values through their selected levels.
    #[doc(hidden)]
    fn write_redacted_map_levels(
        &self,
        fields: &mut RedactionFields<'_, '_>,
        name: &str,
        key_level: Sensitivity,
        value_level: Option<Sensitivity>,
    );
}

impl<K, V> private::Sealed for HashMap<K, V>
where
    K: RedactLevelValue + Debug + Eq + Hash,
    V: RedactLevelValue + Debug,
{
}
impl<K, V> RedactMapKeyValue for HashMap<K, V>
where
    K: RedactLevelValue + Debug + Eq + Hash,
    V: RedactLevelValue + Debug,
{
    /// Writes map entries using the explicitly selected key and optional value
    /// levels.
    fn write_redacted_map_levels(
        &self,
        fields: &mut RedactionFields<'_, '_>,
        name: &str,
        key_level: Sensitivity,
        value_level: Option<Sensitivity>,
    ) {
        fields.map_key_level_entries(name, self.iter(), key_level, value_level);
    }
}
impl<K, V> private::Sealed for BTreeMap<K, V>
where
    K: RedactLevelValue + Debug + Ord,
    V: RedactLevelValue + Debug,
{
}
impl<K, V> RedactMapKeyValue for BTreeMap<K, V>
where
    K: RedactLevelValue + Debug + Ord,
    V: RedactLevelValue + Debug,
{
    /// Writes map entries using the explicitly selected key and optional value
    /// levels.
    fn write_redacted_map_levels(
        &self,
        fields: &mut RedactionFields<'_, '_>,
        name: &str,
        key_level: Sensitivity,
        value_level: Option<Sensitivity>,
    ) {
        fields.map_key_level_entries(name, self.iter(), key_level, value_level);
    }
}
