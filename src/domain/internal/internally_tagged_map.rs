// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serde map adapter for internally tagged newtype variants.

pub(super) struct InternallyTaggedMap<M> {
    /// Underlying serialized map.
    pub(super) map: M,
}

impl<M: serde::ser::SerializeMap> serde::ser::SerializeMap for InternallyTaggedMap<M> {
    type Ok = M::Ok;
    type Error = M::Error;

    fn serialize_key<T: ?Sized + serde::Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.map.serialize_key(key)
    }

    fn serialize_value<T: ?Sized + serde::Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.map.serialize_value(value)
    }

    fn serialize_entry<K: ?Sized + serde::Serialize, V: ?Sized + serde::Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), Self::Error> {
        self.map.serialize_entry(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.map.end()
    }
}

impl<M: serde::ser::SerializeMap> serde::ser::SerializeStruct for InternallyTaggedMap<M> {
    type Ok = M::Ok;
    type Error = M::Error;

    fn serialize_field<T: ?Sized + serde::Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.map.serialize_entry(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.map.end()
    }
}
