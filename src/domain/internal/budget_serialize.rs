// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Resource-admitted borrowing of ordinary Serde values.

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as SerdeError;

use super::budget_serializer::BudgetSerializer;
use super::redact_serialize_scope::admit_node;
use super::serde_node_guard::SerdeNodeGuard;
use super::serde_raw_guard::SerdeRawGuard;

/// Carries a raw value through resource admission without changing sensitivity.
///
/// # Type Parameters
///
/// - `T`: An owned value or borrowed adapter whose ordinary Serde
///   representation is retained. Sensitive fields must use a redacting adapter
///   instead.
#[doc(hidden)]
pub struct BudgetSerialize<T> {
    /// Ordinary value or borrowed custom adapter.
    value: T,
}

impl<T> BudgetSerialize<T> {
    /// Wraps a value; its serializer is invoked exactly once after node
    /// admission. The caller must establish a structured redaction scope before
    /// serializing this wrapper.
    ///
    /// # Parameters
    ///
    /// - `value`: Ordinary value or borrowed adapter moved into this wrapper.
    ///
    /// # Returns
    ///
    /// A lazy carrier; construction neither evaluates nor serializes `value`.
    #[must_use]
    #[inline(always)]
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: Serialize> Serialize for BudgetSerialize<T> {
    /// Admits one node and pins its budget while invoking user Serialize once.
    ///
    /// # Errors
    ///
    /// Returns a structural-budget error when no scope is active or node
    /// admission fails. Propagates input/payload limit errors and errors from
    /// the wrapped value or destination serializer.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Destination serializer and its associated result/error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination invoked after shared node admission.
    ///
    /// # Returns
    ///
    /// The destination result after one budgeted serialization of the value.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !admit_node() {
            return Err(SerdeError::custom("redaction structural budget exceeded"));
        }
        let _node = SerdeNodeGuard;
        let _raw = SerdeRawGuard::new();
        self.value.serialize(BudgetSerializer { inner: serializer })
    }
}
