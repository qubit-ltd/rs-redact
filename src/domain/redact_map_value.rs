// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sealed capability for fields using the `map` mode.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Debug;

use self::internal::sealed as private;
use super::RedactLevelValue;
use super::redaction_fields::RedactionFields;

// Owns the private sealing boundary for supported map representations.
mod internal;

/// Marker capability implemented only for supported string-keyed maps.
#[doc(hidden)]
pub trait RedactMapValue: private::Sealed {
    /// Writes this supported map through the named field scope.
    ///
    /// # Parameters
    ///
    /// - `fields`: Active record scope receiving the map without taking
    ///   ownership.
    /// - `name`: Field label used for admission before classifying map keys.
    #[doc(hidden)]
    fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str);
}

/// Implements map mode for owned key representations and optional maps.
macro_rules! owned_map_key {
    ($key:ty) => {
        impl<V: RedactLevelValue + Debug> RedactMapValue for HashMap<$key, V> {
            /// Traverses an available map through named-field admission and key
            /// classification; absent optional maps use ordinary unmarked output.
            ///
            /// # Parameters
            ///
            /// - `fields`: Active record scope receiving this borrowed map.
            /// - `name`: Field label used for admission and output.
            #[inline]
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                fields.map_entries(name, self.iter());
            }
        }
        impl<V: RedactLevelValue + Debug> RedactMapValue for BTreeMap<$key, V> {
            /// Traverses an available map through named-field admission and key
            /// classification; absent optional maps use ordinary unmarked output.
            ///
            /// # Parameters
            ///
            /// - `fields`: Active record scope receiving this borrowed map.
            /// - `name`: Field label used for admission and output.
            #[inline]
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                fields.map_entries(name, self.iter());
            }
        }
        impl<V: RedactLevelValue + Debug> RedactMapValue for Option<HashMap<$key, V>> {
            /// Traverses an available map through named-field admission and key
            /// classification; absent optional maps use ordinary unmarked output.
            ///
            /// # Parameters
            ///
            /// - `fields`: Active record scope receiving this borrowed map.
            /// - `name`: Field label used for admission and output.
            #[inline]
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                match self {
                    Some(value) => value.write_redacted_map(fields, name),
                    None => {
                        fields.unmarked(name, || self);
                    }
                };
            }
        }
        impl<V: RedactLevelValue + Debug> RedactMapValue for Option<BTreeMap<$key, V>> {
            /// Traverses an available map through named-field admission and key
            /// classification; absent optional maps use ordinary unmarked output.
            ///
            /// # Parameters
            ///
            /// - `fields`: Active record scope receiving this borrowed map.
            /// - `name`: Field label used for admission and output.
            #[inline]
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                match self {
                    Some(value) => value.write_redacted_map(fields, name),
                    None => {
                        fields.unmarked(name, || self);
                    }
                };
            }
        }
    };
}

/// Implements map mode while preserving the borrowed key lifetime.
macro_rules! borrowed_map_key {
    ($key:ty) => {
        impl<'a, V: RedactLevelValue + Debug> RedactMapValue for HashMap<$key, V> {
            /// Traverses an available map through named-field admission and key
            /// classification; absent optional maps use ordinary unmarked output.
            ///
            /// # Parameters
            ///
            /// - `fields`: Active record scope receiving this borrowed map.
            /// - `name`: Field label used for admission and output.
            #[inline]
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                fields.map_entries(name, self.iter());
            }
        }
        impl<'a, V: RedactLevelValue + Debug> RedactMapValue for BTreeMap<$key, V> {
            /// Traverses an available map through named-field admission and key
            /// classification; absent optional maps use ordinary unmarked output.
            ///
            /// # Parameters
            ///
            /// - `fields`: Active record scope receiving this borrowed map.
            /// - `name`: Field label used for admission and output.
            #[inline]
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                fields.map_entries(name, self.iter());
            }
        }
        impl<'a, V: RedactLevelValue + Debug> RedactMapValue for Option<HashMap<$key, V>> {
            /// Traverses an available map through named-field admission and key
            /// classification; absent optional maps use ordinary unmarked output.
            ///
            /// # Parameters
            ///
            /// - `fields`: Active record scope receiving this borrowed map.
            /// - `name`: Field label used for admission and output.
            #[inline]
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                match self {
                    Some(value) => value.write_redacted_map(fields, name),
                    None => {
                        fields.unmarked(name, || self);
                    }
                };
            }
        }
        impl<'a, V: RedactLevelValue + Debug> RedactMapValue for Option<BTreeMap<$key, V>> {
            /// Traverses an available map through named-field admission and key
            /// classification; absent optional maps use ordinary unmarked output.
            ///
            /// # Parameters
            ///
            /// - `fields`: Active record scope receiving this borrowed map.
            /// - `name`: Field label used for admission and output.
            #[inline]
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                match self {
                    Some(value) => value.write_redacted_map(fields, name),
                    None => {
                        fields.unmarked(name, || self);
                    }
                };
            }
        }
    };
}

owned_map_key!(String);
borrowed_map_key!(&'a str);
borrowed_map_key!(Cow<'a, str>);
