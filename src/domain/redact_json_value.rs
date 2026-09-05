// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sealed capability for fields using the `json` mode.

use std::borrow::Cow;

use super::RedactionFields;

mod private {
    pub trait Sealed {}
}

/// Marker capability implemented only for supported JSON text values.
#[doc(hidden)]
pub trait RedactJsonValue: private::Sealed {
    /// Writes this supported JSON text value through the named field scope.
    #[doc(hidden)]
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str);
}

macro_rules! json_text {
    ($($type:ty),+ $(,)?) => {
        $(impl private::Sealed for $type {}
          impl RedactJsonValue for $type {
              fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                  fields.json(name, self.as_ref());
              }
          })+
    };
}

json_text!(String, str, Cow<'_, str>);
impl<T: RedactJsonValue + ?Sized> private::Sealed for &T {}
impl<T: RedactJsonValue + ?Sized> RedactJsonValue for &T {
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        (*self).write_redacted_json(fields, name);
    }
}
impl<T: RedactJsonValue> private::Sealed for Option<T> {}
impl<T: RedactJsonValue> RedactJsonValue for Option<T> {
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        match self {
            Some(value) => value.write_redacted_json(fields, name),
            None => {
                fields.unmarked(name, || Option::<()>::None);
            }
        }
    }
}

impl private::Sealed for serde_json::Value {}
impl RedactJsonValue for serde_json::Value {
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        fields.json_value(name, self);
    }
}
