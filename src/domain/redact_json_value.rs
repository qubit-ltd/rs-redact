//! Sealed capability for fields using the `json` mode.

use std::borrow::Cow;

mod private {
    pub trait Sealed {}
}

/// Marker capability implemented only for supported JSON text values.
#[doc(hidden)]
pub trait RedactJsonValue: private::Sealed {}

macro_rules! json_text {
    ($($type:ty),+ $(,)?) => {
        $(impl private::Sealed for $type {}
          impl RedactJsonValue for $type {})+
    };
}

json_text!(String, str, Cow<'_, str>);
impl private::Sealed for Option<String> {}
impl RedactJsonValue for Option<String> {}
impl private::Sealed for Option<&'_ str> {}
impl RedactJsonValue for Option<&'_ str> {}
impl private::Sealed for Option<Cow<'_, str>> {}
impl RedactJsonValue for Option<Cow<'_, str>> {}
