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
use serde::de::MapAccess;
use serde::de::SeqAccess;
use serde::de::Visitor;
use serde_json::Map;
use serde_json::Number;
use serde_json::Value;

use super::JsonStructureSeed;
use crate::runtime::JsonStructureAdmission;

/// Streams JSON structure through the transaction ledger.
pub(crate) struct JsonStructureVisitor<'admission, 'runtime, 'rejected> {
    /// Narrow structural ledger shared by every nested seed.
    pub(super) admission: &'admission mut JsonStructureAdmission<'runtime>,
    /// Root-inclusive depth of the value currently being decoded.
    pub(super) depth: usize,
    /// Shared flag set when structural limits reject the stream.
    pub(super) rejected: &'rejected mut bool,
}

impl<'de> Visitor<'de> for JsonStructureVisitor<'_, '_, '_> {
    /// Parsed JSON tree assembled from admitted events.
    type Value = Value;

    /// Describes the complete JSON value expected from the deserializer.
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    /// Converts an admitted Boolean event into its JSON representation.
    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Value::Bool(value))
    }

    /// Converts an admitted signed integer into its JSON representation.
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Value::Number(Number::from(value)))
    }

    /// Converts an admitted unsigned integer into its JSON representation.
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Value::Number(Number::from(value)))
    }

    /// Converts a finite admitted float into its JSON number representation.
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    /// Copies a borrowed admitted string into the retained JSON tree.
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    /// Retains an owned admitted string without another allocation.
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Value::String(value))
    }

    /// Maps an absent optional representation to JSON null.
    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Value::Null)
    }

    /// Maps the unit representation to JSON null.
    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Value::Null)
    }

    /// Decodes admitted sequence elements in source order.
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let child_depth = self.depth.saturating_add(1);
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonStructureSeed {
            admission: self.admission,
            depth: child_depth,
            collection_item: true,
            rejected: self.rejected,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    /// Decodes admitted object entries while retaining their parsed keys.
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let child_depth = self.depth.saturating_add(1);
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(JsonStructureSeed {
                admission: self.admission,
                depth: child_depth,
                collection_item: true,
                rejected: self.rejected,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde::de::Expected;
    use serde::de::Visitor;
    use serde::de::value::Error;
    use serde_json::Value;
    use serde_json::json;

    use super::JsonStructureVisitor;
    use crate::RedactionPolicy;
    use crate::runtime::TextSession;
    use crate::runtime::runtime_session::RuntimeSession;

    #[test]
    fn visitor_accepts_owned_strings_and_deserializer_empty_values() {
        let policy = Arc::new(RedactionPolicy::standard());
        let mut session = TextSession::new(policy);
        let mut rejected = false;

        let (mut admission, _) = session.split_json_admission();

        let expectation = format!(
            "{}",
            &JsonStructureVisitor {
                admission: &mut admission,
                depth: 1,
                rejected: &mut rejected,
            } as &dyn Expected,
        );
        let float = Visitor::visit_f64::<Error>(
            JsonStructureVisitor {
                admission: &mut admission,
                depth: 1,
                rejected: &mut rejected,
            },
            1.5,
        )
        .expect("finite float");
        let owned = Visitor::visit_string::<Error>(
            JsonStructureVisitor {
                admission: &mut admission,
                depth: 1,
                rejected: &mut rejected,
            },
            "visible".to_owned(),
        )
        .expect("owned string");
        let none = Visitor::visit_none::<Error>(JsonStructureVisitor {
            admission: &mut admission,
            depth: 1,
            rejected: &mut rejected,
        })
        .expect("none");
        let unit = Visitor::visit_unit::<Error>(JsonStructureVisitor {
            admission: &mut admission,
            depth: 1,
            rejected: &mut rejected,
        })
        .expect("unit");

        assert_eq!(expectation, "a JSON value");
        assert_eq!(float, json!(1.5));
        assert_eq!(owned, Value::String("visible".to_owned()));
        assert_eq!(none, Value::Null);
        assert_eq!(unit, Value::Null);
        assert!(!rejected);
    }
}
