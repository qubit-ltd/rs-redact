// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sealed capability for text and parsed values in fields using the `json`
//! mode.

use std::borrow::Cow;

use serde_json::Value;

use super::RedactionFields;

mod internal;

/// Writes supported JSON representations through a named field scope.
///
/// This hidden support contract accepts `String`, `str`, `Cow<str>`, and parsed
/// [`Value`] values, together with references and optional forms of supported
/// values. Implementations borrow the source without cloning or modifying it.
/// Text is parsed by the field writer; parsed values are traversed directly.
/// `Some` delegates to its value, while `None` writes an unmarked absent value.
/// The sealed boundary prevents downstream implementations.
#[doc(hidden)]
pub trait RedactJsonValue: internal::Sealed {
    /// Writes this borrowed JSON representation under the scope's policy and
    /// budget.
    ///
    /// The name controls field admission rather than classifying the whole
    /// payload; object keys within present JSON values are classified
    /// recursively.
    ///
    /// # Parameters
    ///
    /// * `fields` - Active field scope receiving the output under its current
    ///   policy and budget.
    /// * `name` - Display label used for field admission.
    #[doc(hidden)]
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str);
}

/// Implements the named JSON field operation for borrowed and owned text.
macro_rules! json_text {
    ($($type:ty),+ $(,)?) => {
        $(impl internal::Sealed for $type {}
          impl RedactJsonValue for $type {
              /// Delegates the supported JSON representation to the named-field writer.
              ///
              /// # Parameters
              ///
              /// * `fields` - Active field scope receiving the output under its current policy and budget.
              /// * `name` - Display label used for field admission.
              #[inline]
              fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
                  fields.json(name, self.as_ref());
              }
          })+
    };
}

json_text!(String, str, Cow<'_, str>);
impl<T: RedactJsonValue + ?Sized> internal::Sealed for &T {}
impl<T: RedactJsonValue + ?Sized> RedactJsonValue for &T {
    /// Delegates the supported JSON representation to the named-field writer.
    ///
    /// # Parameters
    ///
    /// * `fields` - Active field scope receiving the output under its current
    ///   policy and budget.
    /// * `name` - Display label used for field admission.
    #[inline]
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        (*self).write_redacted_json(fields, name);
    }
}
impl<T: RedactJsonValue> internal::Sealed for Option<T> {}
impl<T: RedactJsonValue> RedactJsonValue for Option<T> {
    /// Writes the contained JSON representation, or an unmarked absent value
    /// for `None`.
    ///
    /// # Parameters
    ///
    /// * `fields` - Active field scope receiving the output under its current
    ///   policy and budget.
    /// * `name` - Display label used for field admission.
    #[inline]
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        match self {
            Some(value) => value.write_redacted_json(fields, name),
            None => {
                fields.unmarked(name, || Option::<()>::None);
            }
        }
    }
}

impl internal::Sealed for Value {}
impl RedactJsonValue for Value {
    /// Delegates the supported JSON representation to the named-field writer.
    ///
    /// # Parameters
    ///
    /// * `fields` - Active field scope receiving the output under its current
    ///   policy and budget.
    /// * `name` - Display label used for field admission.
    #[inline]
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        fields.json_value(name, self);
    }
}
