// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(all(feature = "derive", feature = "json"))]

use qubit_redact::MaskPolicy;
use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::domain::internal::RedactedSerializeRef;
use serde_json::Value;
use serde_json::json;

#[derive(Redact)]
struct Parsed {
    #[redact(json)]
    data: Value,
}

#[derive(Redact)]
struct Text {
    #[redact(json)]
    data: String,
}

#[test]
fn test_json_special_limits_apply_to_parsed_fields() {
    let raw = r#"{"public":{"inner":"abcdefgh","number":12345,"items":[1,2]}}"#;
    for case in 0..7 {
        let policy = RedactionPolicy::builder()
            .limits(|limits| match case {
                0 => {
                    limits.max_json_string_bytes(1);
                }
                1 => {
                    limits.max_json_depth(1);
                }
                2 => {
                    limits.max_json_nodes(1);
                }
                3 => {
                    limits.max_json_payload_bytes(1);
                }
                4 => {
                    limits.max_json_key_bytes(1);
                }
                5 => {
                    limits.max_json_number_bytes(1);
                }
                _ => {
                    limits.max_json_collection_items(1);
                }
            })
            .expect("limits")
            .build()
            .expect("policy");
        let redactor = Redactor::new(policy.clone());
        let value: Value = serde_json::from_str(raw).expect("valid source JSON");
        let source = Parsed { data: value.clone() };
        let encoded = redactor.to_json(&source).expect("JSON view serializes");
        let viewed = serde_json::to_value(redactor.redact_view(&source)).expect("view serializes");
        assert_eq!(
            serde_json::from_str::<Value>(&encoded).expect("encoded JSON"),
            json!({"data":"<redacted>"}),
            "case {case}"
        );
        assert_eq!(viewed, json!({"data":"<redacted>"}), "case {case}");
        assert_eq!(source.data, value);
        let text = redactor
            .to_json(&Text { data: raw.into() })
            .expect("text JSON view serializes");
        assert_eq!(
            serde_json::from_str::<Value>(&text).expect("encoded text JSON"),
            json!({"data":"<redacted>"})
        );
    }
}

fn json_policy(configure: impl FnOnce(&mut qubit_redact::RedactionLimitsBuilder)) -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(configure)
        .expect("limits")
        .build()
        .expect("policy")
}

#[derive(Redact)]
#[redact(serde)]
struct ValueField {
    #[redact(json)]
    data: Value,
}

#[test]
fn test_json_string_number_key_depth_node_and_collection_boundaries() {
    let cases = [
        (json!({"x":"ab"}), 1, 2, json!({"x":"ab"})),
        (json!({"x":12}), 1, 2, json!({"x":12})),
        (json!({"ab":1}), 1, 2, json!({"ab":1})),
        (json!({"x":1}), 1, 2, json!({"x":1})),
        (json!([1, 2]), 1, 2, json!([1, 2])),
    ];
    for (index, (value, low, high, expected)) in cases.into_iter().enumerate() {
        for limit in [low, high] {
            let policy = json_policy(|limits| match index {
                0 => {
                    limits.max_json_string_bytes(limit);
                }
                1 => {
                    limits.max_json_number_bytes(limit);
                }
                2 => {
                    limits.max_json_key_bytes(limit);
                }
                3 => {
                    limits.max_json_depth(limit);
                    limits.max_json_nodes(limit);
                }
                _ => {
                    limits.max_json_collection_items(limit);
                }
            });
            let actual = serde_json::to_value(RedactedSerializeRef::new(&ValueField { data: value.clone() }, &policy))
                .expect("field serializes");
            if limit == low {
                assert_eq!(actual["data"], "<redacted>", "case {index}");
            } else {
                assert_eq!(actual["data"], expected, "case {index}");
            }
        }
    }
}

#[test]
fn test_json_payload_limit_uses_key_and_scalar_payload_bytes() {
    let source = ValueField {
        data: json!({"x":"ab"}),
    };
    for (maximum, expected) in [(2, json!("<redacted>")), (3, json!({"x":"ab"}))] {
        let policy = json_policy(|limits| {
            limits.max_json_payload_bytes(maximum);
        });
        let actual = serde_json::to_value(RedactedSerializeRef::new(&source, &policy)).expect("value serializes");
        assert_eq!(actual["data"], expected, "payload limit {maximum}");
    }
}

#[derive(Redact)]
#[redact(serde)]
struct TwoValues {
    #[redact(json)]
    first: Value,
    #[redact(json)]
    second: Value,
}

#[test]
fn test_json_special_node_limit_is_per_field() {
    let value = json!({"x":1});
    let source = TwoValues {
        first: value.clone(),
        second: value.clone(),
    };
    let policy = json_policy(|limits| {
        limits.max_json_nodes(2);
    });
    let actual =
        serde_json::to_value(RedactedSerializeRef::new(&source, &policy)).expect("both fields fit individually");
    assert_eq!(actual, json!({"first":{"x":1},"second":{"x":1}}));
}

#[test]
fn test_general_serde_payload_still_accumulates_across_json_fields() {
    let source = TwoValues {
        first: json!("a"),
        second: json!("b"),
    };
    let policy = json_policy(|limits| {
        limits.max_serde_payload_bytes(0);
    });
    assert!(serde_json::to_value(RedactedSerializeRef::new(&source, &policy)).is_err());
}

#[test]
fn test_json_tree_check_does_not_double_charge_general_serde_payload() {
    let source = ValueField { data: json!("x") };
    let policy = json_policy(|limits| {
        limits.max_serde_payload_bytes(1);
    });
    let actual = serde_json::to_value(RedactedSerializeRef::new(&source, &policy))
        .expect("one logical scalar byte fits the shared Serde payload budget");
    assert_eq!(actual, json!({"data":"x"}));
}

#[test]
fn test_rejected_value_fallback_obeys_payload_budget_and_new_scope_recovers() {
    let source = ValueField {
        data: json!({"x":"too long"}),
    };
    let policy = json_policy(|limits| {
        limits.max_json_string_bytes(1).max_serde_payload_bytes(0);
    });
    assert!(serde_json::to_value(RedactedSerializeRef::new(&source, &policy)).is_err());

    let good_policy = json_policy(|limits| {
        limits.max_json_string_bytes(1);
    });
    let actual = serde_json::to_value(RedactedSerializeRef::new(&source, &good_policy)).expect("new scope succeeds");
    assert_eq!(actual["data"], "<redacted>");
}

#[test]
fn test_disabled_skips_json_special_limit_but_keeps_original_tree() {
    let source = ValueField {
        data: json!({"x":"long"}),
    };
    let policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_json_string_bytes(1);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let actual = serde_json::to_value(RedactedSerializeRef::new(&source, &policy)).expect("disabled value serializes");
    assert_eq!(actual["data"], source.data);
}

#[test]
fn test_disabled_value_still_obeys_general_serde_and_final_output_limits() {
    let source = ValueField {
        data: json!({"x":"long"}),
    };
    let serde_policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_json_string_bytes(1).max_serde_payload_bytes(0);
        })
        .expect("limits")
        .build()
        .expect("policy");
    assert!(serde_json::to_value(RedactedSerializeRef::new(&source, &serde_policy)).is_err());

    let output_policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_json_string_bytes(1).max_output_bytes(1);
        })
        .expect("limits")
        .build()
        .expect("policy");
    assert!(Redactor::new(output_policy).to_json(&source).is_err());
}

#[derive(Redact)]
#[redact(serde)]
struct Adapted<'a> {
    #[redact(json)]
    optional: Option<Value>,
    #[redact(json)]
    borrowed: &'a Value,
}

#[test]
fn test_option_and_borrowed_value_adapters_preserve_shape_and_source() {
    let borrowed = json!({"x":"long"});
    let source = Adapted {
        optional: Some(borrowed.clone()),
        borrowed: &borrowed,
    };
    let policy = json_policy(|limits| {
        limits.max_json_string_bytes(1);
    });
    let actual = serde_json::to_value(RedactedSerializeRef::new(&source, &policy)).expect("adapted values serialize");
    assert_eq!(actual["optional"], "<redacted>");
    assert_eq!(actual["borrowed"], "<redacted>");
    assert_eq!(borrowed, json!({"x":"long"}));
    let absent_borrowed = json!("x");
    let absent = Adapted {
        optional: None,
        borrowed: &absent_borrowed,
    };
    let actual = serde_json::to_value(RedactedSerializeRef::new(&absent, &policy)).expect("none serializes");
    assert_eq!(actual["optional"], Value::Null);
}

#[derive(Redact)]
#[redact(serde)]
struct SerdeSource {
    #[redact(json)]
    data: Value,
}

#[test]
fn test_serde_derived_source_uses_json_special_limits() {
    let source = SerdeSource {
        data: json!({"x":"long"}),
    };
    let policy = json_policy(|limits| {
        limits.max_json_string_bytes(1);
    });
    let actual = serde_json::to_value(RedactedSerializeRef::new(&source, &policy)).expect("source serializes");
    assert_eq!(actual["data"], "<redacted>");
}

#[test]
fn test_masked_fallback_payload_must_fit() {
    let source = ValueField {
        data: json!({"x":"long"}),
    };
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.mask(Sensitivity::Secret, MaskPolicy::fixed("mask-that-is-too-long"));
        })
        .expect("mask")
        .limits(|limits| {
            limits.max_json_string_bytes(1).max_serde_payload_bytes(1);
        })
        .expect("limits")
        .build()
        .expect("policy");
    assert!(serde_json::to_value(RedactedSerializeRef::new(&source, &policy)).is_err());
}
