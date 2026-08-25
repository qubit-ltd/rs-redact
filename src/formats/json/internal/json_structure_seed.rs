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
use crate::runtime::runtime_session::RuntimeSession;

/// Charges one JSON value before its contents are decoded.
pub(crate) struct JsonStructureSeed<'session, 'rejected> {
    /// Transaction ledger charged before the deserializer observes a node.
    pub(crate) session: &'session mut dyn RuntimeSession,
    /// Root-inclusive depth assigned to the value being decoded.
    pub(crate) depth: usize,
    /// Whether this value consumes one collection-item allowance.
    pub(crate) collection_item: bool,
    /// Shared rejection flag distinguishing budget failures from syntax errors.
    pub(crate) rejected: &'rejected mut bool,
}

impl<'de> DeserializeSeed<'de> for JsonStructureSeed<'_, '_> {
    /// Parsed JSON tree produced while structural admission is charged.
    type Value = Value;

    /// Admits the pending node before delegating its contents to the visitor.
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if (self.collection_item && !self.session.admit_format_collection_item())
            || !self.session.admit_format_node(self.depth)
        {
            *self.rejected = true;
            return Err(D::Error::custom("JSON structural budget rejected a value"));
        }
        deserializer.deserialize_any(JsonStructureVisitor {
            session: self.session,
            depth: self.depth,
            rejected: self.rejected,
        })
    }
}
