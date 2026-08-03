// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the runtime internally tagged serializer adapter.

#[cfg(feature = "serde")]
use qubit_redact::__private::serialize_internally_tagged;

#[cfg(feature = "serde")]
use serde::{
    Serialize,
    Serializer,
    ser::{
        SerializeMap,
        SerializeStruct,
    },
};

#[cfg(feature = "serde")]
use std::io::{
    self,
    Write,
};

/// Verifies map-like content receives the requested internal tag.
#[cfg(feature = "serde")]
#[test]
fn test_internal_tagged_serializer_inserts_variant_tag() {
    let value = serde_json::json!({"secret": "raw"});
    let rendered = serialize_internally_tagged(
        serde_json::value::Serializer,
        "Event",
        "Payload",
        "kind",
        "Payload",
        &value,
    )
    .expect("map-like content should accept an internal tag");

    assert_eq!(
        rendered,
        serde_json::json!({
            "kind": "Payload",
            "secret": "raw",
        })
    );
}

#[cfg(feature = "serde")]
#[derive(Clone, Copy)]
enum SerializerProbe {
    Bool,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    Char,
    Str,
    Bytes,
    None,
    Some,
    Unit,
    UnitStruct,
    UnitVariant,
    NewtypeStruct,
    NewtypeVariant,
    Seq,
    Tuple,
    TupleStruct,
    TupleVariant,
    Map,
    Struct,
    UnknownLengthMap,
    StructVariant,
}

#[cfg(feature = "serde")]
impl Serialize for SerializerProbe {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Bool => serializer.serialize_bool(true),
            Self::I8 => serializer.serialize_i8(-1),
            Self::I16 => serializer.serialize_i16(-1),
            Self::I32 => serializer.serialize_i32(-1),
            Self::I64 => serializer.serialize_i64(-1),
            Self::U8 => serializer.serialize_u8(1),
            Self::U16 => serializer.serialize_u16(1),
            Self::U32 => serializer.serialize_u32(1),
            Self::U64 => serializer.serialize_u64(1),
            Self::F32 => serializer.serialize_f32(1.0),
            Self::F64 => serializer.serialize_f64(1.0),
            Self::Char => serializer.serialize_char('x'),
            Self::Str => serializer.serialize_str("value"),
            Self::Bytes => serializer.serialize_bytes(b"value"),
            Self::None => serializer.serialize_none(),
            Self::Some => serializer.serialize_some(&"value"),
            Self::Unit => serializer.serialize_unit(),
            Self::UnitStruct => serializer.serialize_unit_struct("Inner"),
            Self::UnitVariant => {
                serializer.serialize_unit_variant("Inner", 0, "inner")
            }
            Self::NewtypeStruct => serializer.serialize_newtype_struct(
                "Inner",
                &serde_json::json!({"value": 1}),
            ),
            Self::NewtypeVariant => serializer.serialize_newtype_variant(
                "Inner",
                0,
                "inner",
                &serde_json::json!({"value": 1}),
            ),
            Self::Seq => {
                let _ = serializer.serialize_seq(Some(0))?;
                unreachable!("the adapter rejects sequences")
            }
            Self::Tuple => {
                let _ = serializer.serialize_tuple(0)?;
                unreachable!("the adapter rejects tuples")
            }
            Self::TupleStruct => {
                let _ = serializer.serialize_tuple_struct("Inner", 0)?;
                unreachable!("the adapter rejects tuple structs")
            }
            Self::TupleVariant => {
                let _ = serializer
                    .serialize_tuple_variant("Inner", 0, "inner", 0)?;
                unreachable!("the adapter rejects tuple variants")
            }
            Self::Map => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("field", &"value")?;
                map.end()
            }
            Self::UnknownLengthMap => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("field", &"value")?;
                map.end()
            }
            Self::Struct => {
                let mut state = serializer.serialize_struct("Inner", 1)?;
                state.serialize_field("field", &"value")?;
                state.end()
            }
            Self::StructVariant => {
                let _ = serializer
                    .serialize_struct_variant("Inner", 0, "inner", 0)?;
                unreachable!("the adapter rejects struct variants")
            }
        }
    }
}

#[cfg(feature = "serde")]
struct FailAfter {
    remaining: usize,
}

#[cfg(feature = "serde")]
impl Write for FailAfter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("intentional serializer failure"));
        }
        let accepted = self.remaining.min(buffer.len());
        self.remaining -= accepted;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_internal_tagged_serializer_covers_supported_shapes() {
    let cases = [
        (
            SerializerProbe::Unit,
            serde_json::json!({"kind": "Payload"}),
        ),
        (
            SerializerProbe::UnitStruct,
            serde_json::json!({"kind": "Payload"}),
        ),
        (
            SerializerProbe::UnitVariant,
            serde_json::json!({"kind": "Payload", "inner": null}),
        ),
        (
            SerializerProbe::NewtypeStruct,
            serde_json::json!({"kind": "Payload", "value": 1}),
        ),
        (
            SerializerProbe::NewtypeVariant,
            serde_json::json!({"kind": "Payload", "inner": {"value": 1}}),
        ),
        (
            SerializerProbe::Map,
            serde_json::json!({"kind": "Payload", "field": "value"}),
        ),
        (
            SerializerProbe::Struct,
            serde_json::json!({"kind": "Payload", "field": "value"}),
        ),
        (
            SerializerProbe::UnknownLengthMap,
            serde_json::json!({"kind": "Payload", "field": "value"}),
        ),
    ];

    for (probe, expected) in cases {
        let rendered = serialize_internally_tagged(
            serde_json::value::Serializer,
            "Event",
            "Payload",
            "kind",
            "Payload",
            &probe,
        )
        .expect("supported content should serialize");
        assert_eq!(rendered, expected);
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_internal_tagged_serializer_propagates_destination_errors() {
    let cases = [
        SerializerProbe::Unit,
        SerializerProbe::UnitStruct,
        SerializerProbe::UnitVariant,
        SerializerProbe::NewtypeStruct,
        SerializerProbe::NewtypeVariant,
        SerializerProbe::Map,
        SerializerProbe::UnknownLengthMap,
        SerializerProbe::Struct,
    ];

    for probe in cases {
        for remaining in 0..64 {
            let mut serializer =
                serde_json::Serializer::new(FailAfter { remaining });
            let _ = serialize_internally_tagged(
                &mut serializer,
                "Event",
                "Payload",
                "kind",
                "Payload",
                &probe,
            );
        }
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_internal_tagged_serializer_rejects_scalar_and_sequence_shapes() {
    let cases = [
        SerializerProbe::Bool,
        SerializerProbe::I8,
        SerializerProbe::I16,
        SerializerProbe::I32,
        SerializerProbe::I64,
        SerializerProbe::U8,
        SerializerProbe::U16,
        SerializerProbe::U32,
        SerializerProbe::U64,
        SerializerProbe::F32,
        SerializerProbe::F64,
        SerializerProbe::Char,
        SerializerProbe::Str,
        SerializerProbe::Bytes,
        SerializerProbe::None,
        SerializerProbe::Some,
        SerializerProbe::Seq,
        SerializerProbe::Tuple,
        SerializerProbe::TupleStruct,
        SerializerProbe::TupleVariant,
        SerializerProbe::StructVariant,
    ];

    for probe in cases {
        let error = serialize_internally_tagged(
            serde_json::value::Serializer,
            "Event",
            "Payload",
            "kind",
            "Payload",
            &probe,
        )
        .expect_err("unsupported content should be rejected");
        assert!(
            error.to_string().contains("Event::Payload"),
            "unexpected serializer error: {error}",
        );
    }
}
