// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serde seed that admits a JSON value before decoding its contents.

use serde::Deserializer;
use serde::de::DeserializeSeed;
use serde::de::Error;
use serde_json::Value;

use super::JsonStructureVisitor;
use crate::runtime::JsonStructureAdmission;

/// Charges one JSON value before its contents are decoded.
pub(crate) struct JsonStructureSeed<'admission, 'runtime, 'rejected> {
    /// Narrow structural ledger charged before materializing a node.
    pub(crate) admission: &'admission mut JsonStructureAdmission<'runtime>,
    /// Root-inclusive depth assigned to the value being decoded.
    pub(crate) depth: usize,
    /// Whether this value consumes one collection-item allowance.
    pub(crate) collection_item: bool,
    /// Shared rejection flag distinguishing budget failures from syntax
    /// errors.
    pub(crate) rejected: &'rejected mut bool,
}

impl<'de> DeserializeSeed<'de> for JsonStructureSeed<'_, '_, '_> {
    /// Parsed JSON tree produced while structural admission is charged.
    type Value = Value;

    /// Admits the pending node, then decodes a JSON value from `deserializer`.
    ///
    /// `D` supplies the borrowed input events. Returns its decoded value or
    /// propagates its decoding error. A rejected collection item or node sets
    /// the shared rejection flag and returns a custom `D::Error` before
    /// decoding. Admitted nodes consume the shared transaction's structural
    /// allowance.
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if (self.collection_item && !self.admission.admit_collection_item()) || !self.admission.admit_node(self.depth) {
            *self.rejected = true;
            return Err(D::Error::custom("JSON structural budget rejected a value"));
        }
        deserializer.deserialize_any(JsonStructureVisitor {
            admission: self.admission,
            depth: self.depth,
            rejected: self.rejected,
        })
    }
}
