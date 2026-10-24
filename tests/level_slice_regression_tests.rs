// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Borrowed level slices preserve safe sequence serialization.

#![cfg(all(feature = "derive", feature = "serde", feature = "json"))]

use qubit_redact::MaskPolicy;
use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::domain::internal::RedactedSerializeRef;

#[derive(Redact)]
#[redact(serde)]
struct BorrowedValues<'a> {
    #[redact(level = "secret")]
    values: &'a [String],
}

#[derive(Redact)]
#[redact(serde)]
struct BorrowedArray<'a> {
    #[redact(level = "secret")]
    values: &'a [String; 2],
}

#[derive(Redact)]
#[redact(serde)]
struct BorrowedStrValues<'a> {
    #[redact(level = "secret")]
    values: &'a [&'a str],
}

#[derive(Redact)]
#[redact(serde)]
struct BorrowedLevelValues<'a> {
    #[redact(level = "low")]
    low: &'a [String],
    #[redact(level = "medium")]
    medium: &'a [String],
    #[redact(level = "high")]
    high: &'a [String],
    #[redact(level = "secret")]
    secret: &'a [String],
}

#[derive(Redact)]
#[redact(serde)]
struct BorrowedLowValues<'a> {
    #[redact(level = "low")]
    values: &'a [String],
}

#[derive(Redact)]
#[redact(serde)]
struct NestedBorrowedValues<'a> {
    #[redact(nested)]
    inner: BorrowedValues<'a>,
}

#[test]
fn test_borrowed_slice_redacts_leaf_values_without_copying() {
    let values = ["first-secret".to_owned(), "second-secret".to_owned()];
    let value = BorrowedValues { values: &values };
    let redactor = Redactor::standard();

    let text = redactor.redact_text(&value);
    assert!(!text.text().as_str().contains("first-secret"));
    assert!(!text.text().as_str().contains("second-secret"));
    let view = serde_json::to_value(RedactedSerializeRef::new(
        &value,
        &RedactionPolicy::standard(),
    ))
    .expect("borrowed slice view should serialize");
    assert_eq!(
        view["values"],
        serde_json::json!(["<redacted>", "<redacted>"])
    );
    serde_test::assert_ser_tokens(
        &RedactedSerializeRef::new(&value, &RedactionPolicy::standard()),
        &[
            serde_test::Token::Struct {
                name: "BorrowedValues",
                len: 1,
            },
            serde_test::Token::Str("values"),
            serde_test::Token::Seq { len: Some(2) },
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::SeqEnd,
            serde_test::Token::StructEnd,
        ],
    );
    let json = redactor
        .to_json(&value)
        .expect("borrowed slice JSON should serialize");
    assert!(!json.contains("first-secret"));

    let vector = vec!["vec-secret".to_owned()];
    let borrowed_vector = BorrowedValues { values: &vector };
    let encoded = serde_json::to_value(RedactedSerializeRef::new(
        &borrowed_vector,
        &RedactionPolicy::standard(),
    ))
    .expect("borrowed Vec slice should serialize without copying");
    assert_eq!(encoded["values"], serde_json::json!(["<redacted>"]));

    let empty: [String; 0] = [];
    let empty_value = BorrowedValues { values: &empty };
    let view = serde_json::to_value(RedactedSerializeRef::new(
        &empty_value,
        &RedactionPolicy::standard(),
    ))
    .expect("empty borrowed slice should serialize");
    assert_eq!(view["values"], serde_json::json!([]));
}

#[test]
fn test_borrowed_str_slice_and_fixed_array_keep_their_serde_shapes() {
    let words = ["first", "second"];
    let borrowed_words = BorrowedStrValues { values: &words };
    let policy = RedactionPolicy::standard();
    let view = serde_json::to_value(RedactedSerializeRef::new(&borrowed_words, &policy))
        .expect("borrowed str slice should serialize");
    assert_eq!(
        view["values"],
        serde_json::json!(["<redacted>", "<redacted>"])
    );

    let array = ["one".to_owned(), "two".to_owned()];
    let value = BorrowedArray { values: &array };
    let view = serde_json::to_value(RedactedSerializeRef::new(&value, &policy))
        .expect("fixed array view should serialize");
    assert_eq!(
        view["values"],
        serde_json::json!(["<redacted>", "<redacted>"])
    );
    serde_test::assert_ser_tokens(
        &RedactedSerializeRef::new(&value, &policy),
        &[
            serde_test::Token::Struct {
                name: "BorrowedArray",
                len: 1,
            },
            serde_test::Token::Str("values"),
            serde_test::Token::Tuple { len: 2 },
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::TupleEnd,
            serde_test::Token::StructEnd,
        ],
    );
}

#[test]
fn test_slice_levels_and_disabled_mode_keep_their_existing_representations() {
    let values = ["raw-secret".to_owned()];
    let value = BorrowedLevelValues {
        low: &values,
        medium: &values,
        high: &values,
        secret: &values,
    };
    let enabled = serde_json::to_value(RedactedSerializeRef::new(
        &value,
        &RedactionPolicy::standard(),
    ))
    .expect("all level slices should serialize");
    assert!(!enabled.to_string().contains("raw-secret"));

    let disabled = serde_json::to_value(RedactedSerializeRef::new(
        &value,
        &RedactionPolicy::disabled(),
    ))
    .expect("disabled level slices should serialize");
    for field in ["low", "medium", "high", "secret"] {
        assert_eq!(disabled[field], serde_json::json!(["raw-secret"]));
    }
}

#[test]
fn test_slice_collection_limit_uses_the_shared_safe_fallback() {
    let values = ["first-secret".to_owned(), "second-secret".to_owned()];
    let value = BorrowedValues { values: &values };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("collection limit should be valid")
        .build()
        .expect("collection limit should build");

    let encoded = serde_json::to_value(RedactedSerializeRef::new(&value, &policy))
        .expect("collection rejection should use its safe fallback");
    assert_eq!(encoded["values"], "<redacted>");
    assert!(!encoded.to_string().contains("first-secret"));
    assert!(!encoded.to_string().contains("second-secret"));
}

#[test]
fn test_slice_input_depth_and_payload_limits_share_the_active_scope() {
    let input_values = ["raw-input".to_owned()];
    let input_value = BorrowedLowValues {
        values: &input_values,
    };
    let input_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(0);
        })
        .expect("input limit should be valid")
        .build()
        .expect("input limit should build");
    let encoded = serde_json::to_value(RedactedSerializeRef::new(&input_value, &input_policy))
        .expect("input exhaustion should use the safe scalar fallback");
    assert_eq!(encoded["values"], serde_json::json!(["<redacted>"]));
    assert!(!encoded.to_string().contains("raw-input"));

    let nested_values = ["raw-depth".to_owned()];
    let nested_value = NestedBorrowedValues {
        inner: BorrowedValues {
            values: &nested_values,
        },
    };
    let depth_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(1);
        })
        .expect("depth limit should be valid")
        .build()
        .expect("depth limit should build");
    let encoded = serde_json::to_value(RedactedSerializeRef::new(&nested_value, &depth_policy))
        .expect("depth exhaustion should use the safe nested fallback");
    assert!(!encoded.to_string().contains("raw-depth"));

    let payload_values = ["raw-payload".to_owned()];
    let payload_value = BorrowedValues {
        values: &payload_values,
    };
    let payload_policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.mask(Sensitivity::Low, MaskPolicy::preserve_edges(1, 1, "#", 0));
        })
        .expect("mask policy should be valid")
        .limits(|limits| {
            limits.max_serde_payload_bytes(1);
        })
        .expect("payload limit should be valid")
        .build()
        .expect("payload limit should build");
    assert!(
        serde_json::to_value(RedactedSerializeRef::new(&payload_value, &payload_policy)).is_err()
    );
}

#[test]
fn test_slice_values_consume_one_cumulative_input_budget() {
    let values = ["abc".to_owned(), "def".to_owned()];
    let value = BorrowedLowValues { values: &values };
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.mask(Sensitivity::Low, MaskPolicy::preserve_edges(1, 1, "#", 0));
        })
        .expect("mask policy should be valid")
        .limits(|limits| {
            limits.max_input_bytes(5);
        })
        .expect("input limit should be valid")
        .build()
        .expect("input limit should build");
    let encoded = serde_json::to_value(RedactedSerializeRef::new(&value, &policy))
        .expect("slice should use its single shared input budget");
    assert_eq!(encoded["values"], serde_json::json!(["a#c", "<redacted>"]));
    assert!(!encoded.to_string().contains("def"));
}
