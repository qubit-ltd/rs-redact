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
pub(super) struct InternallyTaggedMap<M> {
    /// Underlying serialized map.
    pub(super) map: M,
}

impl<M: SerializeMap> SerializeMap for InternallyTaggedMap<M> {
    /// Underlying map success value.
    type Ok = M::Ok;
    /// Underlying map error, preserved without conversion.
    type Error = M::Error;

    /// Forwards the admitted key without changing its wire representation.
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
    /// # Errors
    ///
    /// Propagates errors from the underlying map serializer.
    #[inline(always)]
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.map.serialize_value(value)
    }

    /// Preserves paired-entry serialization on the underlying map.
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
    /// # Errors
    ///
    /// Propagates errors from the underlying map serializer.
    #[inline(always)]
    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error> {
        self.map.serialize_entry(key, value)
    }

    /// Finalizes the tagged map and propagates its encoding result.
    ///
    /// # Errors
    ///
    /// Propagates errors from the underlying map serializer.
    #[inline(always)]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.map.end()
    }
}
