//! Sealed capability for fields using the `map` mode.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;

mod private {
    pub trait Sealed {}
}

/// Marker capability implemented only for supported string-keyed maps.
#[doc(hidden)]
pub trait RedactMapValue: private::Sealed {}

macro_rules! owned_map_key {
    ($key:ty) => {
        impl<V: super::RedactLevelValue> private::Sealed for HashMap<$key, V> {}
        impl<V: super::RedactLevelValue> RedactMapValue for HashMap<$key, V> {}
        impl<V: super::RedactLevelValue> private::Sealed for BTreeMap<$key, V> {}
        impl<V: super::RedactLevelValue> RedactMapValue for BTreeMap<$key, V> {}
        impl<V: super::RedactLevelValue> private::Sealed for Option<HashMap<$key, V>> {}
        impl<V: super::RedactLevelValue> RedactMapValue for Option<HashMap<$key, V>> {}
        impl<V: super::RedactLevelValue> private::Sealed for Option<BTreeMap<$key, V>> {}
        impl<V: super::RedactLevelValue> RedactMapValue for Option<BTreeMap<$key, V>> {}
    };
}

macro_rules! borrowed_map_key {
    ($key:ty) => {
        impl<'a, V: super::RedactLevelValue> private::Sealed for HashMap<$key, V> {}
        impl<'a, V: super::RedactLevelValue> RedactMapValue for HashMap<$key, V> {}
        impl<'a, V: super::RedactLevelValue> private::Sealed for BTreeMap<$key, V> {}
        impl<'a, V: super::RedactLevelValue> RedactMapValue for BTreeMap<$key, V> {}
        impl<'a, V: super::RedactLevelValue> private::Sealed for Option<HashMap<$key, V>> {}
        impl<'a, V: super::RedactLevelValue> RedactMapValue for Option<HashMap<$key, V>> {}
        impl<'a, V: super::RedactLevelValue> private::Sealed for Option<BTreeMap<$key, V>> {}
        impl<'a, V: super::RedactLevelValue> RedactMapValue for Option<BTreeMap<$key, V>> {}
    };
}

owned_map_key!(String);
borrowed_map_key!(&'a str);
borrowed_map_key!(Cow<'a, str>);
