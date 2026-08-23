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
use crate::RedactionSession;

/// Charges one JSON value before its contents are decoded.
pub(crate) struct JsonStructureSeed<'session, 'rejected> {
    pub(crate) session: &'session mut RedactionSession,
    pub(crate) depth: usize,
    pub(crate) collection_item: bool,
    pub(crate) rejected: &'rejected mut bool,
}

impl<'de> DeserializeSeed<'de> for JsonStructureSeed<'_, '_> {
    type Value = Value;

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
