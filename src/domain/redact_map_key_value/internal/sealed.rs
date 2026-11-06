// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sealed implementations for maps supporting explicit key sensitivity.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

use crate::domain::RedactLevelValue;

/// Restricts the map-key capability to supported map representations.
pub trait Sealed {
    // empty
}

impl<K, V> Sealed for HashMap<K, V>
where
    K: RedactLevelValue + Debug + Eq + Hash,
    V: RedactLevelValue + Debug,
{
}

impl<K, V> Sealed for BTreeMap<K, V>
where
    K: RedactLevelValue + Debug + Ord,
    V: RedactLevelValue + Debug,
{
}
