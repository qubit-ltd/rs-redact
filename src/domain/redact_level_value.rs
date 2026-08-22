//! Sealed capability for fields using the `level` mode.

use std::borrow::Cow;

mod private {
    pub trait Sealed {}
}

/// Marker capability implemented only for values supported by `level`.
#[doc(hidden)]
pub trait RedactLevelValue: private::Sealed {}

macro_rules! scalar {
    ($($type:ty),+ $(,)?) => {
        $(impl private::Sealed for $type {}
          impl RedactLevelValue for $type {})+
    };
}

scalar!(
    String,
    str,
    Cow<'_, str>,
    char,
    bool,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    f32,
    f64
);

impl<T: RedactLevelValue> private::Sealed for Option<T> {}
impl<T: RedactLevelValue> RedactLevelValue for Option<T> {}
impl<T: RedactLevelValue> private::Sealed for Vec<T> {}
impl<T: RedactLevelValue> RedactLevelValue for Vec<T> {}
impl<T: RedactLevelValue, const N: usize> private::Sealed for [T; N] {}
impl<T: RedactLevelValue, const N: usize> RedactLevelValue for [T; N] {}

macro_rules! tuple {
    ($($name:ident),+) => {
        impl<$($name: RedactLevelValue),+> private::Sealed for ($($name,)+) {}
        impl<$($name: RedactLevelValue),+> RedactLevelValue for ($($name,)+) {}
    };
}

tuple!(A);
tuple!(A, B);
tuple!(A, B, C);
tuple!(A, B, C, D);
tuple!(A, B, C, D, E);
tuple!(A, B, C, D, E, F);
tuple!(A, B, C, D, E, F, G);
tuple!(A, B, C, D, E, F, G, H);
tuple!(A, B, C, D, E, F, G, H, I);
tuple!(A, B, C, D, E, F, G, H, I, J);
tuple!(A, B, C, D, E, F, G, H, I, J, K);
tuple!(A, B, C, D, E, F, G, H, I, J, K, L);
