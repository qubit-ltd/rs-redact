// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sealed capability for fields using the `json` mode.

use std::borrow::Cow;

use serde_json::Value;

use super::RedactionFields;

/// Seals the supported capability set against downstream implementations.
mod private {
    /// Restricts this capability to the supported representations.
    pub trait Sealed {
        // empty
    }
}

/// Marker capability implemented only for supported JSON text values.
#[doc(hidden)]
pub trait RedactJsonValue: private::Sealed {
    /// Writes this supported JSON text value through the named field scope.
    #[doc(hidden)]
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str);
}

/// Implements the named JSON field operation for borrowed and owned text.
macro_rules! json_text {
    ($($type:ty),+ $(,)?) => {
        $(impl private::Sealed for $type {}
          impl RedactJsonValue for $type {
              /// Delegates the supported JSON representation to the named-field writer.
              fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                  fields.json(name, self.as_ref());
              }
          })+
    };
}

json_text!(String, str, Cow<'_, str>);
impl<T: RedactJsonValue + ?Sized> private::Sealed for &T {}
impl<T: RedactJsonValue + ?Sized> RedactJsonValue for &T {
    /// Delegates the supported JSON representation to the named-field writer.
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        (*self).write_redacted_json(fields, name);
    }
}
impl<T: RedactJsonValue> private::Sealed for Option<T> {}
impl<T: RedactJsonValue> RedactJsonValue for Option<T> {
    /// Delegates the supported JSON representation to the named-field writer.
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        match self {
            Some(value) => value.write_redacted_json(fields, name),
            None => {
                fields.unmarked(name, || Option::<()>::None);
            }
        }
    }
}

impl private::Sealed for Value {}
impl RedactJsonValue for Value {
    /// Delegates the supported JSON representation to the named-field writer.
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        fields.json_value(name, self);
    }
}
