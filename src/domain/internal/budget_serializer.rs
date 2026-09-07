// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Single-pass admission of ordinary Serde events.

use std::fmt;
use std::fmt::Display;

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as SerdeError;

use super::bounded_display_writer::BoundedDisplayWriter;
use super::budget_compound::BudgetCompound;
use super::budget_serialize::BudgetSerialize;
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::admit_input;
use super::redact_serialize_scope::admit_payload;
use super::redact_serialize_scope::remaining_input_bytes;
use super::redact_serialize_scope::remaining_payload_bytes;

/// Streams Serde events through the active shared resource budget.
///
/// # Type Parameters
///
/// - `S`: Downstream serializer receiving admitted Serde events.
pub(super) struct BudgetSerializer<S> {
    /// Serializer receiving events after the shared budget has admitted them.
    pub(super) inner: S,
}

/// Charges one scalar's logical bytes before forwarding it.
///
/// # Errors
///
/// Returns a serializer error for either source or payload exhaustion.
///
/// # Type Parameters
///
/// - `E`: Serializer error type used to report admission failure.
///
/// # Parameters
///
/// - `bytes`: Logical scalar byte count charged to source and payload.
///
/// # Returns
///
/// Success after both source and logical payload byte counts are admitted.
fn scalar<E: SerdeError>(bytes: usize) -> Result<(), E> {
    if !admit_input(bytes) {
        return Err(E::custom("redaction input budget exceeded"));
    }
    if !admit_payload(bytes) {
        return Err(E::custom("redaction scalar payload budget exceeded"));
    }
    Ok(())
}

/// Charges collection entries before invoking any child serializer.
///
/// # Errors
///
/// Returns a serializer error when the shared collection allowance is
/// exhausted.
///
/// # Type Parameters
///
/// - `E`: Serializer error type used to report admission failure.
///
/// # Parameters
///
/// - `count`: Collection entries to admit before visiting children.
///
/// # Returns
///
/// Success after the shared collection allowance admits all requested entries.
#[inline]
pub(super) fn items<E: SerdeError>(count: usize) -> Result<(), E> {
    if admit_collection_items(count) {
        Ok(())
    } else {
        Err(E::custom("redaction collection budget exceeded"))
    }
}

impl<S: Serializer> Serializer for BudgetSerializer<S> {
    /// Downstream successful result, preserved without conversion.
    type Ok = S::Ok;
    /// Downstream error type used for admission failures as well.
    type Error = S::Error;
    /// Compound adapter that keeps child serialization inside the shared
    /// budget.
    type SerializeSeq = BudgetCompound<S::SerializeSeq>;
    /// Compound adapter that keeps child serialization inside the shared
    /// budget.
    type SerializeTuple = BudgetCompound<S::SerializeTuple>;
    /// Compound adapter that keeps child serialization inside the shared
    /// budget.
    type SerializeTupleStruct = BudgetCompound<S::SerializeTupleStruct>;
    /// Compound adapter that keeps child serialization inside the shared
    /// budget.
    type SerializeTupleVariant = BudgetCompound<S::SerializeTupleVariant>;
    /// Compound adapter that keeps child serialization inside the shared
    /// budget.
    type SerializeMap = BudgetCompound<S::SerializeMap>;
    /// Compound adapter that keeps child serialization inside the shared
    /// budget.
    type SerializeStruct = BudgetCompound<S::SerializeStruct>;
    /// Compound adapter that keeps child serialization inside the shared
    /// budget.
    type SerializeStructVariant = BudgetCompound<S::SerializeStructVariant>;
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_bool(self, value: bool) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_bool(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_i8(self, value: i8) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i8(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_i16(self, value: i16) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i16(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_i32(self, value: i32) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i32(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_i64(self, value: i64) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i64(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i128(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u8(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_u16(self, value: u16) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u16(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u32(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_u64(self, value: u64) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u64(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u128(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_f32(value)
    }
    /// Charges the scalar representation before forwarding its native Serde
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_f64(value)
    }
    /// Charges source and logical payload bytes before forwarding this scalar.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.len_utf8())?;
        self.inner.serialize_char(value)
    }
    /// Charges source and logical payload bytes before forwarding this scalar.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.len())?;
        self.inner.serialize_str(value)
    }
    /// Charges source and logical payload bytes before forwarding this scalar.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.len())?;
        self.inner.serialize_bytes(value)
    }
    /// Forwards an empty scalar without charging encoder-specific framing.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(0)?;
        self.inner.serialize_none()
    }
    /// Forwards an empty scalar without charging encoder-specific framing.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(0)?;
        self.inner.serialize_unit()
    }
    /// Wraps the contained value so it joins the active budget when serialized.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized serializable source type.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_some(&BudgetSerialize::new(value))
    }
    /// Forwards the static unit-struct label without treating it as payload.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `name`: Static source type name.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_unit_struct(name)
    }
    /// Admits the variant label as a scalar before forwarding it.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `name`: Static source type name.
    /// - `index`: Source variant index.
    /// - `variant`: Static variant label.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(variant.len())?;
        self.inner.serialize_unit_variant(name, index, variant)
    }
    /// Wraps the contained value so it joins the active budget when serialized.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized serializable source type.
    ///
    /// # Parameters
    ///
    /// - `name`: Static source type name.
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_newtype_struct(name, &BudgetSerialize::new(value))
    }
    /// Wraps the contained value so it joins the active budget when serialized.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized serializable source type.
    ///
    /// # Parameters
    ///
    /// - `name`: Static source type name.
    /// - `index`: Source variant index.
    /// - `variant`: Static variant label.
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.inner
            .serialize_newtype_variant(name, index, variant, &BudgetSerialize::new(value))
    }
    /// Captures Display once under both limits and preserves writer versus
    /// formatter failure.
    ///
    /// # Errors
    ///
    /// Returns an error for writer rejection or an independent Display failure,
    /// or propagates input/payload admission and downstream serializer errors.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized displayable source type.
    ///
    /// # Parameters
    ///
    /// - `value`: Source event value.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    fn collect_str<T: ?Sized + Display>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        let input = remaining_input_bytes();
        let payload = remaining_payload_bytes();
        let mut writer = BoundedDisplayWriter::new(input.min(payload));
        let result = fmt::write(&mut writer, format_args!("{value}"));
        let text = writer.finish().ok_or_else(|| {
            SerdeError::custom(if input <= payload {
                "redaction input budget exceeded"
            } else {
                "redaction scalar payload budget exceeded"
            })
        })?;
        result.map_err(|_| SerdeError::custom("redaction scalar formatting failed"))?;
        self.serialize_str(&text)
    }
    /// Preserves the downstream encoding preference without accessing the
    /// source.
    ///
    /// # Returns
    ///
    /// The downstream encoding preference.
    #[inline(always)]
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
    /// Prepays declared entries and returns a compound that admits every child.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `len`: Declared collection length; unknown hints defer admission to
    ///   each entry.
    ///
    /// # Returns
    ///
    /// The admitted compound adapter used to serialize its children.
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        if let Some(count) = len {
            items::<S::Error>(count)?;
        }
        Ok(BudgetCompound {
            inner: self.inner.serialize_seq(len)?,
            remaining: len.unwrap_or(0),
        })
    }
    /// Prepays declared entries and returns a compound that admits every child.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `len`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// The admitted compound adapter used to serialize its children.
    #[inline]
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_tuple(len)?,
            remaining: len,
        })
    }
    /// Prepays declared entries and returns a compound that admits every child.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `name`: Static source type name.
    /// - `len`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// The admitted compound adapter used to serialize its children.
    #[inline]
    fn serialize_tuple_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeTupleStruct, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_tuple_struct(name, len)?,
            remaining: len,
        })
    }
    /// Prepays declared entries and returns a compound that admits every child.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `name`: Static source type name.
    /// - `index`: Source variant index.
    /// - `variant`: Static variant label.
    /// - `len`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// The admitted compound adapter used to serialize its children.
    #[inline]
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_tuple_variant(name, index, variant, len)?,
            remaining: len,
        })
    }
    /// Prepays declared entries and returns a compound that admits every child.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `len`: Declared collection length; unknown hints defer admission to
    ///   each entry.
    ///
    /// # Returns
    ///
    /// The admitted compound adapter used to serialize its children.
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        if let Some(count) = len {
            items::<S::Error>(count)?;
        }
        Ok(BudgetCompound {
            inner: self.inner.serialize_map(len)?,
            remaining: len.unwrap_or(0),
        })
    }
    /// Prepays declared entries and returns a compound that admits every child.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `name`: Static source type name.
    /// - `len`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// The admitted compound adapter used to serialize its children.
    #[inline]
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeStruct, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_struct(name, len)?,
            remaining: len,
        })
    }
    /// Prepays declared entries and returns a compound that admits every child.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serializer failures.
    ///
    /// # Parameters
    ///
    /// - `name`: Static source type name.
    /// - `index`: Source variant index.
    /// - `variant`: Static variant label.
    /// - `len`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// The admitted compound adapter used to serialize its children.
    #[inline]
    fn serialize_struct_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_struct_variant(name, index, variant, len)?,
            remaining: len,
        })
    }
}
