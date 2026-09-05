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
#[doc(hidden)]
pub struct BudgetSerialize<T> {
    /// Ordinary value or borrowed custom adapter.
    value: T,
}

impl<T> BudgetSerialize<T> {
    /// Wraps a value; its serializer is invoked exactly once after node
    /// admission.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: Serialize> Serialize for BudgetSerialize<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !admit_node() {
            return Err(SerdeError::custom("redaction structural budget exceeded"));
        }
        let _node = SerdeNodeGuard;
        let _raw = SerdeRawGuard::new();
        self.value.serialize(BudgetSerializer { inner: serializer })
    }
}
