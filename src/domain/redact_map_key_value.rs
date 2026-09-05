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
use std::hash::Hash;

use super::RedactLevelValue;
use super::RedactionFields;
use crate::Sensitivity;

mod private {
    pub trait Sealed {}
}

/// Capability implemented for supported maps with level-capable keys.
#[doc(hidden)]
pub trait RedactMapKeyValue: private::Sealed {
    /// Writes keys at `level` while retaining ordinary values.
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
    K: RedactLevelValue + Eq + Hash,
    V: RedactLevelValue,
{
}
impl<K, V> RedactMapKeyValue for HashMap<K, V>
where
    K: RedactLevelValue + Eq + Hash,
    V: RedactLevelValue,
{
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
    K: RedactLevelValue + Ord,
    V: RedactLevelValue,
{
}
impl<K, V> RedactMapKeyValue for BTreeMap<K, V>
where
    K: RedactLevelValue + Ord,
    V: RedactLevelValue,
{
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
