// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serde map adapter for internally tagged newtype variants.

use serde::Serialize;
use serde::ser::SerializeMap;
use serde::ser::SerializeStruct;

/// Forwards map and struct entries to the underlying Serde map serializer.
///
/// The adapter keeps the serializer's success and error types unchanged while
/// presenting both compound serialization interfaces over the same map.
///
/// # Type Parameters
///
/// - `M`: Map serializer that receives every serialized entry.
pub(super) struct InternallyTaggedMap<M> {
    /// Map serializer that owns the output state for the tagged value.
    pub(super) map: M,
}

impl<M: SerializeMap> SerializeMap for InternallyTaggedMap<M> {
    /// Underlying map success value.
    type Ok = M::Ok;
    /// Underlying map error, preserved without conversion.
    type Error = M::Error;

    /// Forwards the admitted key without changing its wire representation.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized serializable key type.
    ///
    /// # Parameters
    ///
    /// - `key`: Key to serialize for the already admitted map entry.
    ///
    /// # Returns
    ///
    /// Success after the underlying serializer accepts the key.
    ///
    /// # Errors
    ///
    /// Propagates errors from the underlying map serializer.
    #[inline(always)]
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.map.serialize_key(key)
    }

    /// Forwards the admitted value without changing its wire representation.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized serializable value type.
    ///
    /// # Parameters
    ///
    /// - `value`: Value to serialize for the previously admitted key.
    ///
    /// # Returns
    ///
    /// Success after the underlying serializer accepts the value.
    ///
    /// # Errors
    ///
    /// Propagates errors from the underlying map serializer.
    #[inline(always)]
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.map.serialize_value(value)
    }

    /// Preserves paired-entry serialization on the underlying map.
    ///
    /// # Type Parameters
    ///
    /// - `K`: Possibly unsized serializable key type.
    /// - `V`: Possibly unsized serializable value type.
    ///
    /// # Parameters
    ///
    /// - `key`: Key to serialize as one map entry.
    /// - `value`: Value paired with the key.
    ///
    /// # Returns
    ///
    /// Success after the underlying serializer accepts the entry.
    ///
    /// # Errors
    ///
    /// Propagates errors from the underlying map serializer.
    #[inline(always)]
    fn serialize_entry<K: ?Sized + Serialize, V: ?Sized + Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), Self::Error> {
        self.map.serialize_entry(key, value)
    }

    /// Finalizes the tagged map and propagates its encoding result.
    ///
    /// # Returns
    ///
    /// The underlying map serializer's completed output.
    ///
    /// # Errors
    ///
    /// Propagates errors from the underlying map serializer.
    #[inline(always)]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.map.end()
    }
}

impl<M: SerializeMap> SerializeStruct for InternallyTaggedMap<M> {
    /// Underlying map success value.
    type Ok = M::Ok;
    /// Underlying map error, preserved without conversion.
    type Error = M::Error;

    /// Emits a struct field as a map entry beside the injected tag.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized serializable field value type.
    ///
    /// # Parameters
    ///
    /// - `key`: Static struct field name serialized as the map key.
    /// - `value`: Field value to serialize.
    ///
    /// # Returns
    ///
    /// Success after the underlying serializer accepts the field entry.
    ///
    /// # Errors
    ///
    /// Propagates errors from the underlying map serializer.
    #[inline(always)]
    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error> {
        self.map.serialize_entry(key, value)
    }

    /// Finalizes the tagged map and propagates its encoding result.
    ///
    /// # Returns
    ///
    /// The underlying map serializer's completed output.
    ///
    /// # Errors
    ///
    /// Propagates errors from the underlying map serializer.
    #[inline(always)]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.map.end()
    }
}
