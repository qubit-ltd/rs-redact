// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

#![cfg(all(feature = "derive", feature = "serde"))]

use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::domain::internal::RedactedSerializeRef;
use qubit_redact_derive::Redact;
use serde::Serialize;
use serde::Serializer;

#[derive(Redact)]
#[redact(serde)]
struct Levels {
    #[redact(level = "secret")]
    values: Vec<Vec<String>>,
}

#[derive(Redact)]
#[redact(serde)]
struct Plain {
    value: String,
}

#[derive(Redact)]
#[redact(serde)]
struct Keyed {
    key: String,
    #[redact(keyed_by = key)]
    value: String,
}

/// Builds a policy that admits only four source bytes.
fn small_input_policy() -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(4);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy")
}

#[test]
fn test_level_collection_obeys_depth_and_nodes() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(1);
            limits.max_nodes(1);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let value = Levels {
        values: vec![vec!["secret".into(); 3]; 3],
    };
    let actual = serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).expect("safe marker");
    assert_eq!(actual["values"], policy.masking().mask_opaque(Sensitivity::Secret));
}

#[test]
fn test_plain_field_obeys_input_budget() {
    let policy = small_input_policy();
    let value = Plain {
        value: "x".repeat(1000),
    };
    assert!(serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).is_err());
}

#[test]
fn test_keyed_passthrough_obeys_input_budget() {
    let policy = small_input_policy();
    let value = Keyed {
        key: "foo".into(),
        value: "x".repeat(1000),
    };
    assert!(serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).is_err());
}

#[derive(Redact)]
#[redact(serde)]
struct LevelString {
    #[redact(level = "secret")]
    value: String,
}

#[derive(Redact)]
#[redact(serde)]
struct MapValues {
    #[redact(map)]
    values: std::collections::BTreeMap<String, String>,
}

/// Disabled scalar serialization must still respect the payload allowance.
#[test]
fn test_disabled_level_obeys_output_budget() {
    let policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_output_bytes(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let value = LevelString {
        value: "abcd".to_owned(),
    };
    assert!(serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).is_err());
}

/// Map pass-through and disabled values share ordinary scalar admission.
#[test]
fn test_map_passthrough_and_disabled_values_obey_input_budget() {
    for base in [RedactionPolicy::standard(), RedactionPolicy::disabled()] {
        let policy = base
            .to_builder()
            .limits(|limits| {
                limits.max_input_bytes(4);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let value = MapValues {
            values: std::collections::BTreeMap::from([("foo".to_owned(), "x".repeat(1000))]),
        };
        assert!(serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).is_err());
    }
}

/// Direct nested collection adapters must count their container nodes.
#[test]
fn test_nested_collections_obey_depth_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(1);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let value = vec![vec![LevelString {
        value: "secret".to_owned(),
    }]];
    let actual = serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).expect("safe marker");
    assert_eq!(actual, serde_json::json!(["<redacted>"]));
}

/// A custom serializer's size hint is not permission to emit unlimited entries.
#[test]
fn test_custom_sequence_cannot_bypass_collection_limit_with_inaccurate_length() {
    #[derive(Debug)]
    struct ExtraItems;
    impl Serialize for ExtraItems {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut sequence = serializer.serialize_seq(Some(0))?;
            sequence.serialize_element(&1_u8)?;
            sequence.serialize_element(&2_u8)?;
            sequence.end()
        }
    }
    #[derive(Redact)]
    #[redact(serde)]
    struct Envelope {
        value: ExtraItems,
    }
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    assert!(serde_json::to_value(RedactedSerializeRef::new(&Envelope { value: ExtraItems }, &policy)).is_err());
}

/// Explicitly masked keys and unmarked values must both use payload admission.
#[test]
fn test_map_key_adapter_obeys_input_and_output_budgets() {
    use qubit_redact::domain::internal::RedactedMapKeySerializeRef;
    let values = std::collections::BTreeMap::from([("key".to_owned(), "x".repeat(1000))]);
    let input_policy = small_input_policy();
    assert!(
        serde_json::to_value(RedactedMapKeySerializeRef::new(
            &values,
            &input_policy,
            Sensitivity::Low,
            None,
        ))
        .is_err()
    );
    let output_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    assert!(
        serde_json::to_value(RedactedMapKeySerializeRef::new(
            &values,
            &output_policy,
            Sensitivity::Secret,
            Some(Sensitivity::Secret),
        ))
        .is_err()
    );
}

/// Ordinary Serde shapes retain their wire representation under admission.
#[test]
fn test_ordinary_serde_shapes_preserve_wire_values() {
    #[derive(Debug, Serialize)]
    enum Shape {
        Unit,
        Newtype(u32),
        Tuple(bool, char),
        Struct { number: i64, text: String },
    }
    #[derive(Debug, Serialize)]
    struct Payload {
        signed: (i8, i16, i32, i64, i128),
        unsigned: (u8, u16, u32, u64, u128),
        floats: (f32, f64),
        option: (Option<String>, Option<String>),
        unit: (),
        shapes: Vec<Shape>,
        map: std::collections::BTreeMap<String, Vec<u8>>,
    }
    #[derive(Redact)]
    #[redact(serde)]
    struct Envelope {
        payload: Payload,
    }
    let value = Envelope {
        payload: Payload {
            signed: (-1, -2, -3, -4, -5),
            unsigned: (1, 2, 3, 4, 5),
            floats: (1.5, 2.5),
            option: (Some("visible".into()), None),
            unit: (),
            shapes: vec![
                Shape::Unit,
                Shape::Newtype(7),
                Shape::Tuple(true, '界'),
                Shape::Struct {
                    number: -9,
                    text: "shown".into(),
                },
            ],
            map: std::collections::BTreeMap::from([("region".into(), vec![1, 2])]),
        },
    };
    let expected = serde_json::to_value(&value.payload).expect("ordinary serialization");
    let actual = serde_json::to_value(RedactedSerializeRef::new(&value, &RedactionPolicy::standard()))
        .expect("admitted serialization");
    assert_eq!(actual["payload"], expected);
}

/// Admission does not measure custom serializers by invoking them twice.
#[test]
fn test_custom_serializer_runs_once_and_shares_scalar_budget() {
    use std::cell::Cell;

    use serde::ser::SerializeSeq;
    #[derive(Debug)]
    struct Counted<'a>(&'a Cell<usize>);
    impl Serialize for Counted<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.set(self.0.get() + 1);
            let mut output = serializer.serialize_seq(None)?;
            output.serialize_element("ab")?;
            output.serialize_element("cd")?;
            output.end()
        }
    }
    #[derive(Redact)]
    #[redact(serde)]
    struct Envelope<'a> {
        value: Counted<'a>,
    }
    for (maximum, succeeds) in [(4, true), (3, false)] {
        let calls = Cell::new(0);
        let value = Envelope { value: Counted(&calls) };
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_input_bytes(maximum).max_output_bytes(maximum);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let actual = serde_json::to_value(RedactedSerializeRef::new(&value, &policy));
        assert_eq!(actual.is_ok(), succeeds);
        assert_eq!(calls.get(), 1);
        if succeeds {
            assert_eq!(actual.expect("admitted"), serde_json::json!({"value": ["ab", "cd"]}));
        }
    }
}

/// Display-based custom serialization stops when its writer rejects a chunk.
#[test]
fn test_custom_collect_str_stops_at_budget() {
    use std::cell::Cell;
    use std::fmt;
    #[derive(Debug)]
    struct Counted<'a>(&'a Cell<usize>);
    impl fmt::Display for Counted<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            for _ in 0..1000 {
                self.0.set(self.0.get() + 1);
                formatter.write_str("abcd")?;
            }
            Ok(())
        }
    }
    impl Serialize for Counted<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_str(self)
        }
    }
    #[derive(Redact)]
    #[redact(serde)]
    struct Envelope<'a> {
        value: Counted<'a>,
    }
    let calls = Cell::new(0);
    let value = Envelope { value: Counted(&calls) };
    let actual = serde_json::to_value(RedactedSerializeRef::new(&value, &small_input_policy()));
    assert!(actual.is_err());
    assert_eq!(calls.get(), 2);
}

/// A nested derived Serialize must not replace its caller's resource budget.
#[test]
fn test_unmarked_nested_derive_cannot_reset_outer_budget() {
    #[derive(Debug, Redact)]
    #[redact(serde)]
    struct Inner {
        value: String,
    }
    #[derive(Redact)]
    #[redact(serde)]
    struct Outer {
        inner: Inner,
    }
    let value = Outer {
        inner: Inner {
            value: "x".repeat(1000),
        },
    };
    let actual = serde_json::to_value(RedactedSerializeRef::new(&value, &small_input_policy()));
    assert!(actual.is_err());
}

/// Unwinding a custom serializer releases both depth and policy-scope pins.
#[test]
fn test_panicking_serializer_does_not_poison_later_operations() {
    use std::panic::catch_unwind;
    #[derive(Debug)]
    struct Panics;
    impl Serialize for Panics {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            panic!("intentional serializer panic");
        }
    }
    #[derive(Redact)]
    #[redact(serde)]
    struct Envelope {
        value: Panics,
    }
    let policy = small_input_policy();
    assert!(
        catch_unwind(|| serde_json::to_value(RedactedSerializeRef::new(&Envelope { value: Panics }, &policy))).is_err()
    );
    let ordinary = Plain { value: "abcd".into() };
    assert_eq!(
        serde_json::to_value(RedactedSerializeRef::new(&ordinary, &policy)).expect("fresh budget"),
        serde_json::json!({"value": "abcd"})
    );
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
