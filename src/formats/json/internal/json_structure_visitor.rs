// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Streaming visitor that admits JSON structure without a value tree.

use std::fmt;

use serde::de::Error;
use serde::de::IgnoredAny;
use serde::de::MapAccess;
use serde::de::SeqAccess;
use serde::de::Visitor;

use super::JsonStructureSeed;
use crate::RedactionSession;

/// Streams JSON structure through the transaction ledger.
pub(crate) struct JsonStructureVisitor<'session, 'rejected> {
    pub(super) session: &'session mut RedactionSession,
    pub(super) depth: usize,
    pub(super) rejected: &'rejected mut bool,
}

impl<'de> Visitor<'de> for JsonStructureVisitor<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let child_depth = self.depth.saturating_add(1);
        while sequence
            .next_element_seed(JsonStructureSeed {
                session: self.session,
                depth: child_depth,
                collection_item: true,
                rejected: self.rejected,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let child_depth = self.depth.saturating_add(1);
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(JsonStructureSeed {
                session: self.session,
                depth: child_depth,
                collection_item: true,
                rejected: self.rejected,
            })?;
        }
        Ok(())
    }
}
