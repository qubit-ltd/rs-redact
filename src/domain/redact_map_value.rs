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

use super::redaction_fields::RedactionFields;

mod private {
    pub trait Sealed {}
}

/// Marker capability implemented only for supported string-keyed maps.
#[doc(hidden)]
pub trait RedactMapValue: private::Sealed {
    /// Writes this supported map through the named field scope.
    #[doc(hidden)]
    fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str);
}

macro_rules! owned_map_key {
    ($key:ty) => {
        impl<V: super::RedactLevelValue> private::Sealed for HashMap<$key, V> {}
        impl<V: super::RedactLevelValue> RedactMapValue for HashMap<$key, V> {
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                fields.map_entries(name, self.iter());
            }
        }
        impl<V: super::RedactLevelValue> private::Sealed for BTreeMap<$key, V> {}
        impl<V: super::RedactLevelValue> RedactMapValue for BTreeMap<$key, V> {
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                fields.map_entries(name, self.iter());
            }
        }
        impl<V: super::RedactLevelValue> private::Sealed for Option<HashMap<$key, V>> {}
        impl<V: super::RedactLevelValue> RedactMapValue for Option<HashMap<$key, V>> {
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                match self {
                    Some(value) => value.write_redacted_map(fields, name),
                    None => {
                        fields.unmarked(name, || self);
                    }
                };
            }
        }
        impl<V: super::RedactLevelValue> private::Sealed for Option<BTreeMap<$key, V>> {}
        impl<V: super::RedactLevelValue> RedactMapValue for Option<BTreeMap<$key, V>> {
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

macro_rules! borrowed_map_key {
    ($key:ty) => {
        impl<'a, V: super::RedactLevelValue> private::Sealed for HashMap<$key, V> {}
        impl<'a, V: super::RedactLevelValue> RedactMapValue for HashMap<$key, V> {
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                fields.map_entries(name, self.iter());
            }
        }
        impl<'a, V: super::RedactLevelValue> private::Sealed for BTreeMap<$key, V> {}
        impl<'a, V: super::RedactLevelValue> RedactMapValue for BTreeMap<$key, V> {
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                fields.map_entries(name, self.iter());
            }
        }
        impl<'a, V: super::RedactLevelValue> private::Sealed for Option<HashMap<$key, V>> {}
        impl<'a, V: super::RedactLevelValue> RedactMapValue for Option<HashMap<$key, V>> {
            fn write_redacted_map(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                match self {
                    Some(value) => value.write_redacted_map(fields, name),
                    None => {
                        fields.unmarked(name, || self);
                    }
                };
            }
        }
        impl<'a, V: super::RedactLevelValue> private::Sealed for Option<BTreeMap<$key, V>> {}
        impl<'a, V: super::RedactLevelValue> RedactMapValue for Option<BTreeMap<$key, V>> {
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
