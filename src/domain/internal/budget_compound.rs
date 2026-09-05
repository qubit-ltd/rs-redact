// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Child admission for ordinary compound serializers.

use serde::Serialize;
use serde::ser::Error as SerdeError;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;
use serde::ser::SerializeStruct;
use serde::ser::SerializeStructVariant;
use serde::ser::SerializeTuple;
use serde::ser::SerializeTupleStruct;
use serde::ser::SerializeTupleVariant;

use super::budget_serialize::BudgetSerialize;
use super::budget_serializer::items;

/// Delegates a compound while wrapping each child before user code runs.
pub(super) struct BudgetCompound<C> {
    /// Downstream compound serializer.
    pub(super) inner: C,
    /// Declared entries already charged but not yet emitted.
    pub(super) remaining: usize,
}
impl<C> BudgetCompound<C> {
    /// Consumes one prepaid entry or admits an entry beyond the size hint.
    /// Returns an error before child serialization when the budget is
    /// exhausted.
    fn admit_item<E: SerdeError>(&mut self) -> Result<(), E> {
        if self.remaining > 0 {
            self.remaining -= 1;
            Ok(())
        } else {
            items(1)
        }
    }
}

impl<C: SerializeSeq> SerializeSeq for BudgetCompound<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.admit_item::<C::Error>()?;
        self.inner.serialize_element(&BudgetSerialize::new(value))
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}
impl<C: SerializeTuple> SerializeTuple for BudgetCompound<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.admit_item::<C::Error>()?;
        self.inner.serialize_element(&BudgetSerialize::new(value))
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}
impl<C: SerializeTupleStruct> SerializeTupleStruct for BudgetCompound<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.admit_item::<C::Error>()?;
        self.inner.serialize_field(&BudgetSerialize::new(value))
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}
impl<C: SerializeTupleVariant> SerializeTupleVariant for BudgetCompound<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.admit_item::<C::Error>()?;
        self.inner.serialize_field(&BudgetSerialize::new(value))
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}
impl<C: SerializeMap> SerializeMap for BudgetCompound<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.admit_item::<C::Error>()?;
        self.inner.serialize_key(&BudgetSerialize::new(key))
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.inner.serialize_value(&BudgetSerialize::new(value))
    }
    /// Admits both children through the destination's paired-entry operation.
    fn serialize_entry<K: ?Sized + Serialize, V: ?Sized + Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), Self::Error> {
        self.admit_item::<C::Error>()?;
        self.inner
            .serialize_entry(&BudgetSerialize::new(key), &BudgetSerialize::new(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}
impl<C: SerializeStruct> SerializeStruct for BudgetCompound<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error> {
        self.admit_item::<C::Error>()?;
        self.inner.serialize_field(key, &BudgetSerialize::new(value))
    }
    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.inner.skip_field(key)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}
impl<C: SerializeStructVariant> SerializeStructVariant for BudgetCompound<C> {
    type Ok = C::Ok;
    type Error = C::Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error> {
        self.admit_item::<C::Error>()?;
        self.inner.serialize_field(key, &BudgetSerialize::new(value))
    }
    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.inner.skip_field(key)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}
