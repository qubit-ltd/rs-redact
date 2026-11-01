// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public-boundary tests for resource-admitted Serde serialization.

#![cfg(feature = "serde")]

use proptest::strategy::Strategy;
use qubit_redact::RedactionPolicy;
use qubit_redact::domain::internal::BudgetSerialize;
use qubit_redact::domain::internal::RedactSerializeScope;
use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap;
use serde_test::Token;

#[derive(Serialize)]
struct Newtype(u8);

#[derive(Serialize)]
struct TupleStruct(u8, u8);

#[derive(Serialize)]
struct Record {
    value: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    omitted: Option<u8>,
}

struct Bytes<'a>(&'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

struct SeparateMap;

impl Serialize for SeparateMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_key("value")?;
        map.serialize_value(&11_u8)?;
        map.end()
    }
}

struct EntryMap;

impl Serialize for EntryMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("entry", &12_u8)?;
        map.end()
    }
}

struct HumanReadable;

impl Serialize for HumanReadable {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str("human-readable")
        } else {
            serializer.serialize_u8(0)
        }
    }
}

struct CollectedDisplay;

impl std::fmt::Display for CollectedDisplay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("collected label")
    }
}

impl Serialize for CollectedDisplay {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Serialize)]
enum EnumShape {
    Unit,
    Newtype(u8),
    Tuple(u8, u8),
    Record {
        value: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        omitted: Option<u8>,
    },
}

/// Runs an ordinary Serde value through the active resource budget.
fn serialize_budgeted<T: Serialize>(value: &T) -> serde_json::Value {
    let policy = RedactionPolicy::standard();
    let _scope = RedactSerializeScope::new(&policy);
    BudgetSerialize::new(value)
        .serialize(serde_json::value::Serializer)
        .expect("value should serialize within the default budget")
}

/// Newtypes, tuple structs, byte strings, and compound entries retain their
/// ordinary Serde representation after budget admission.
#[test]
fn test_budget_serializer_forwards_serde_shapes() {
    assert_eq!(serialize_budgeted(&Newtype(7)), serde_json::json!(7));
    assert_eq!(serialize_budgeted(&TupleStruct(3, 5)), serde_json::json!([3, 5]));
    assert_eq!(serialize_budgeted(&Bytes(b"abc")), serde_json::json!([97, 98, 99]));
    assert_eq!(
        serialize_budgeted(&Record {
            value: 9,
            omitted: None
        }),
        serde_json::json!({"value": 9})
    );
    assert_eq!(serialize_budgeted(&SeparateMap), serde_json::json!({"value": 11}));
    assert_eq!(serialize_budgeted(&EntryMap), serde_json::json!({"entry": 12}));
    assert_eq!(serialize_budgeted(&Some(13_u8)), serde_json::json!(13));
    assert_eq!(serialize_budgeted(&Option::<u8>::None), serde_json::Value::Null);
    assert_eq!(serialize_budgeted(&HumanReadable), serde_json::json!("human-readable"));
    assert_eq!(
        serialize_budgeted(&CollectedDisplay),
        serde_json::json!("collected label")
    );
    assert_eq!(serialize_budgeted(&EnumShape::Unit), serde_json::json!("Unit"));
    assert_eq!(
        serialize_budgeted(&EnumShape::Newtype(13)),
        serde_json::json!({"Newtype": 13})
    );
    assert_eq!(
        serialize_budgeted(&EnumShape::Tuple(2, 3)),
        serde_json::json!({"Tuple": [2, 3]})
    );
    assert_eq!(
        serialize_budgeted(&EnumShape::Record {
            value: 17,
            omitted: None,
        }),
        serde_json::json!({"Record": {"value": 17}})
    );
}

fn policy_for_scalar_limits(input: usize, payload: usize) -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(input).max_serde_payload_bytes(payload);
        })
        .expect("limits should build")
        .build()
        .expect("policy should build")
}

fn assert_scalar_boundaries<T: Serialize + std::fmt::Display>(value: T) {
    let bytes = value.to_string().len();
    for (input, payload, succeeds) in [
        (bytes, bytes, true),
        (bytes - 1, bytes, false),
        (bytes, bytes - 1, false),
    ] {
        let policy = policy_for_scalar_limits(input, payload);
        let _scope = RedactSerializeScope::new(&policy);
        let mut output = Vec::new();
        let result = BudgetSerialize::new(&value).serialize(&mut serde_json::Serializer::new(&mut output));
        if succeeds {
            result.expect("exact input and payload budgets should admit the scalar");
        } else {
            let error = result.expect_err("one byte below either limit should reject the scalar");
            let message = error.to_string();
            let expected = if input < bytes {
                "redaction input budget exceeded"
            } else {
                "redaction scalar payload budget exceeded"
            };
            assert!(message.contains(expected), "unexpected error: {message}");
            assert!(
                !message.contains(&value.to_string()),
                "error exposed scalar value: {message}"
            );
            assert!(
                output.is_empty(),
                "downstream serializer received rejected scalar bytes: {output:?}"
            );
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config { cases: 32, .. proptest::test_runner::Config::default() })]

    #[test]
    fn test_budget_serializer_generated_integer_lengths(value in proptest::prelude::any::<i128>()) {
        assert_scalar_boundaries(value);
    }

    #[test]
    fn test_budget_serializer_generated_float_lengths(value in proptest::prelude::any::<f64>().prop_filter("finite float", |value| value.is_finite())) {
        assert_scalar_boundaries(value);
    }
}

#[test]
fn test_budget_serializer_scalar_display_length_boundaries() {
    assert_scalar_boundaries(false);
    assert_scalar_boundaries(true);
    macro_rules! integer_cases {
        ($($type:ty),+ $(,)?) => {$({
            assert_scalar_boundaries(0 as $type);
            assert_scalar_boundaries(1 as $type);
            assert_scalar_boundaries(10 as $type);
            assert_scalar_boundaries(<$type>::MIN);
            assert_scalar_boundaries(<$type>::MAX);
        })+};
    }
    integer_cases!(i8, i16, i32, i64, i128, u8, u16, u32, u64, u128);
    for value in [
        0.0_f32,
        -0.0,
        f32::MIN_POSITIVE,
        f32::MIN,
        f32::MAX,
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        1.25,
    ] {
        assert_scalar_boundaries(value);
    }
    for value in [
        0.0_f64,
        -0.0,
        f64::MIN_POSITIVE,
        f64::MIN,
        f64::MAX,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        1.25,
    ] {
        assert_scalar_boundaries(value);
    }
}

#[test]
fn test_budget_serializer_forwards_native_scalar_events() {
    macro_rules! assert_event {
        ($value:expr, $token:expr) => {{
            let policy = RedactionPolicy::standard();
            let _scope = RedactSerializeScope::new(&policy);
            serde_test::assert_ser_tokens(&BudgetSerialize::new(&$value), &[$token]);
        }};
    }
    assert_event!(true, Token::Bool(true));
    assert_event!(false, Token::Bool(false));
    assert_event!(-7_i8, Token::I8(-7));
    assert_event!(-700_i16, Token::I16(-700));
    assert_event!(-70_000_i32, Token::I32(-70_000));
    assert_event!(-70_000_i64, Token::I64(-70_000));
    assert_event!(7_u8, Token::U8(7));
    assert_event!(700_u16, Token::U16(700));
    assert_event!(70_000_u32, Token::U32(70_000));
    assert_event!(70_000_u64, Token::U64(70_000));
    assert_event!(1.25_f32, Token::F32(1.25));
    assert_event!(1.25_f64, Token::F64(1.25));
}

#[test]
fn test_budget_serializer_forwards_wide_integer_events() {
    // serde_test has no i128/u128 token variants; verify their native output
    // through serde_json instead.
    for (value, expected) in [(-70_000_i128, "-70000"), (70_000_i128, "70000")] {
        let policy = RedactionPolicy::standard();
        let _scope = RedactSerializeScope::new(&policy);
        let mut output = Vec::new();
        BudgetSerialize::new(&value)
            .serialize(&mut serde_json::Serializer::new(&mut output))
            .expect("wide integer should serialize");
        assert_eq!(output, expected.as_bytes());
    }
    for (value, expected) in [
        (70_000_u128, "70000"),
        (u128::MAX, "340282366920938463463374607431768211455"),
    ] {
        let policy = RedactionPolicy::standard();
        let _scope = RedactSerializeScope::new(&policy);
        let mut output = Vec::new();
        BudgetSerialize::new(&value)
            .serialize(&mut serde_json::Serializer::new(&mut output))
            .expect("wide unsigned integer should serialize");
        assert_eq!(output, expected.as_bytes());
    }
}
