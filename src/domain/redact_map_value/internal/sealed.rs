// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sealing trait for supported string-keyed map representations.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Debug;

use crate::domain::RedactLevelValue;

/// Restricts map mode to the string-keyed representations supported by this
/// crate.
///
/// The containing module is private, preventing downstream implementations.
pub trait Sealed {
    // empty
}

impl<V: RedactLevelValue + Debug> Sealed for HashMap<String, V> {}

impl<V: RedactLevelValue + Debug> Sealed for Option<HashMap<String, V>> {}

impl<V: RedactLevelValue + Debug> Sealed for BTreeMap<String, V> {}

impl<V: RedactLevelValue + Debug> Sealed for Option<BTreeMap<String, V>> {}

impl<V: RedactLevelValue + Debug> Sealed for HashMap<&str, V> {}

impl<V: RedactLevelValue + Debug> Sealed for Option<HashMap<&str, V>> {}

impl<V: RedactLevelValue + Debug> Sealed for BTreeMap<&str, V> {}

impl<V: RedactLevelValue + Debug> Sealed for Option<BTreeMap<&str, V>> {}

impl<'a, V: RedactLevelValue + Debug> Sealed for HashMap<Cow<'a, str>, V> {}

impl<'a, V: RedactLevelValue + Debug> Sealed for Option<HashMap<Cow<'a, str>, V>> {}

impl<'a, V: RedactLevelValue + Debug> Sealed for BTreeMap<Cow<'a, str>, V> {}

impl<'a, V: RedactLevelValue + Debug> Sealed for Option<BTreeMap<Cow<'a, str>, V>> {}
