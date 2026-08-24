// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sealed capability for fields using the `level` mode.

use std::borrow::Cow;
use std::fmt::Debug;

use super::RedactionItems;
use super::RedactionWriter;
use crate::Sensitivity;

mod private {
    pub trait Sealed {}
}

/// Capability implemented only for values supported by `level`.
#[doc(hidden)]
pub trait RedactLevelValue: private::Sealed + Debug {
    #[doc(hidden)]
    fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity);
}

macro_rules! scalar {
    ($($type:ty),+ $(,)?) => {
        $(impl private::Sealed for $type {}
          impl RedactLevelValue for $type {
              fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity) {
                  writer.write_level_scalar(level, self);
              }
          })+
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

#[cfg(feature = "serde")]
impl private::Sealed for bigdecimal::BigDecimal {}
#[cfg(feature = "serde")]
impl RedactLevelValue for bigdecimal::BigDecimal {
    fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity) {
        writer.write_level_scalar(level, self);
    }
}

impl<T: RedactLevelValue + ?Sized> private::Sealed for &T {}
impl<T: RedactLevelValue + ?Sized> RedactLevelValue for &T {
    fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity) {
        (*self).write_redacted_level(writer, level);
    }
}

impl<T: RedactLevelValue> private::Sealed for Option<T> {}
impl<T: RedactLevelValue> RedactLevelValue for Option<T> {
    fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity) {
        match self {
            Some(value) => {
                writer.literal("Some(");
                value.write_redacted_level(writer, level);
                writer.literal(")");
            }
            None => writer.literal("None"),
        }
    }
}
impl<T: RedactLevelValue> private::Sealed for Vec<T> {}
impl<T: RedactLevelValue> RedactLevelValue for Vec<T> {
    fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity) {
        writer.sequence(|items| write_items(items, self.iter(), level));
    }
}
impl<T: RedactLevelValue, const N: usize> private::Sealed for [T; N] {}
impl<T: RedactLevelValue, const N: usize> RedactLevelValue for [T; N] {
    fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity) {
        writer.sequence(|items| write_items(items, self.iter(), level));
    }
}

fn write_items<'value, T, I>(items: &mut RedactionItems<'_, '_>, values: I, level: Sensitivity)
where
    T: RedactLevelValue + 'value,
    I: IntoIterator<Item = &'value T>,
{
    for value in values {
        items.level_value(value, level);
    }
}

macro_rules! tuple {
    ($($index:tt:$name:ident),+) => {
        impl<$($name: RedactLevelValue),+> private::Sealed for ($($name,)+) {}
        impl<$($name: RedactLevelValue),+> RedactLevelValue for ($($name,)+) {
            fn write_redacted_level(&self, writer: &mut RedactionWriter<'_>, level: Sensitivity) {
                writer.level_tuple(|items| {
                    $(items.level_value(&self.$index, level);)+
                });
            }
        }
    };
}

tuple!(0:A);
tuple!(0:A, 1:B);
tuple!(0:A, 1:B, 2:C);
tuple!(0:A, 1:B, 2:C, 3:D);
tuple!(0:A, 1:B, 2:C, 3:D, 4:E);
tuple!(0:A, 1:B, 2:C, 3:D, 4:E, 5:F);
tuple!(0:A, 1:B, 2:C, 3:D, 4:E, 5:F, 6:G);
tuple!(0:A, 1:B, 2:C, 3:D, 4:E, 5:F, 6:G, 7:H);
tuple!(0:A, 1:B, 2:C, 3:D, 4:E, 5:F, 6:G, 7:H, 8:I);
tuple!(0:A, 1:B, 2:C, 3:D, 4:E, 5:F, 6:G, 7:H, 8:I, 9:J);
tuple!(0:A, 1:B, 2:C, 3:D, 4:E, 5:F, 6:G, 7:H, 8:I, 9:J, 10:K);
tuple!(0:A, 1:B, 2:C, 3:D, 4:E, 5:F, 6:G, 7:H, 8:I, 9:J, 10:K, 11:L);
