//! Sealed capability for fields using the `json` mode.

use std::borrow::Cow;

use super::RedactionFields;

mod private {
    pub trait Sealed {}
}

/// Marker capability implemented only for supported JSON text values.
#[doc(hidden)]
pub trait RedactJsonValue: private::Sealed {
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
impl private::Sealed for &'_ str {}
impl RedactJsonValue for &'_ str {
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        fields.json(name, self);
    }
}
impl private::Sealed for Option<String> {}
impl RedactJsonValue for Option<String> {
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        match self {
            Some(value) => fields.json(name, value),
            None => fields.unmarked(name, || self),
        };
    }
}
impl private::Sealed for Option<&'_ str> {}
impl RedactJsonValue for Option<&'_ str> {
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        match self {
            Some(value) => fields.json(name, value),
            None => fields.unmarked(name, || self),
        };
    }
}
impl private::Sealed for Option<Cow<'_, str>> {}
impl RedactJsonValue for Option<Cow<'_, str>> {
    fn write_redacted_json(&self, fields: &mut RedactionFields<'_, '_>, name: &str) {
        match self {
            Some(value) => fields.json(name, value.as_ref()),
            None => fields.unmarked(name, || self),
        };
    }
}
