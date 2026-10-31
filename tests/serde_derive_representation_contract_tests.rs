// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(all(feature = "derive", feature = "serde"))]
#![allow(non_camel_case_types)]

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use serde::Serialize;

thread_local! {
    static TRANSPARENT_PREDICATE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn count_if_empty<T: AsRef<str>>(value: &T) -> bool {
    TRANSPARENT_PREDICATE_CALLS.with(|calls| calls.set(calls.get() + 1));
    value.as_ref().is_empty()
}

#[derive(Serialize)]
#[serde(transparent)]
struct NativeConditionalNamed {
    #[serde(skip_serializing_if = "count_if_empty")]
    value: String,
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(transparent)]
struct ConditionalNamed {
    #[serde(skip_serializing_if = "count_if_empty")]
    value: String,
}

#[derive(Serialize)]
#[serde(transparent)]
struct NativeConditionalTuple(#[serde(skip_serializing_if = "count_if_empty")] String);

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(transparent)]
struct ConditionalTuple(#[serde(skip_serializing_if = "count_if_empty")] String);

#[derive(Serialize)]
struct OrdinaryConditional {
    #[serde(skip_serializing_if = "count_if_empty")]
    value: String,
}

#[derive(Serialize)]
#[serde(rename = "ConditionalNewtype")]
struct NativeConditionalNewtype(#[serde(skip_serializing_if = "count_if_empty")] String);

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(rename = "ConditionalNewtype")]
struct ConditionalNewtype(#[serde(skip_serializing_if = "count_if_empty")] String);

fn serialize_string<S: serde::Serializer>(value: &String, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(rename = "AdaptedNewtype")]
struct AdaptedNewtype(#[serde(skip_serializing_if = "count_if_empty", serialize_with = "serialize_string")] String);

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(rename = "SkippedNewtype")]
struct SkippedNewtype(#[redact(skip)] #[serde(skip_serializing_if = "count_if_empty")] String);

#[derive(Serialize)]
#[serde(rename = "ConditionalSkipStruct")]
#[allow(dead_code)]
struct NativeConditionalSkipStruct {
    #[serde(rename = "wire_optional", skip_serializing_if = "count_if_empty")]
    optional: String,
    visible: String,
    #[serde(skip)]
    never: String,
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(rename = "ConditionalSkipStruct")]
struct ConditionalSkipStruct {
    #[serde(rename = "wire_optional", skip_serializing_if = "count_if_empty")]
    optional: String,
    visible: String,
    #[serde(skip)]
    never: String,
}

#[derive(Serialize)]
#[serde(rename = "SkipEvent")]
enum NativeConditionalSkipEvent {
    #[serde(rename = "payload")]
    Payload {
        #[serde(rename = "wire_optional", skip_serializing_if = "count_if_empty")]
        optional: String,
        visible: String,
        #[serde(skip)]
        never: String,
    },
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(rename = "SkipEvent")]
enum ConditionalSkipEvent {
    #[serde(rename = "payload")]
    Payload {
        #[serde(rename = "wire_optional", skip_serializing_if = "count_if_empty")]
        optional: String,
        visible: String,
        #[serde(skip)]
        never: String,
    },
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct RedactSkipConditional {
    #[redact(skip)]
    #[serde(rename = "wire_optional", skip_serializing_if = "count_if_empty")]
    optional: String,
    visible: String,
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(transparent)]
struct TransparentSkipped(#[redact(skip)] String);

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(transparent)]
struct TransparentNamed {
    #[redact(level = "secret")]
    value: String,
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(transparent)]
struct TransparentTuple(#[redact(level = "secret")] String);

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct OrdinaryNewtype(#[redact(level = "secret")] String);

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct NestedBudget {
    first: String,
    second: String,
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(transparent)]
struct TransparentBudget(#[redact(nested)] NestedBudget);

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(tag = "kind", content = "payload", rename = "WireEvent", rename_all = "kebab-case")]
#[allow(non_camel_case_types)]
enum AdjacentEvent {
    Unit,
    Tuple(#[redact(level = "secret")] String),
    Newtype(#[redact(level = "secret")] String),
    #[serde(rename = "wire-name")]
    Named {
        #[redact(level = "secret")]
        secret: String,
    },
    Empty {},
    r#type {
        #[redact(level = "secret")]
        secret: String,
    },
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(untagged, rename = "WireEvent")]
enum UntaggedEvent {
    Named {
        #[redact(level = "secret")]
        secret: String,
    },
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(tag = "kind", content = "payload")]
enum GenericAdjacent<__QubitRedactAdjacentTag> {
    Data(__QubitRedactAdjacentTag),
}

fn check_transparent_tokens<T: serde::Serialize>(value: &T, token: serde_test::Token) {
    serde_test::assert_ser_tokens(value, &[token]);
}

#[test]
fn test_transparent_named_source_and_view_forward_inner_event() {
    let source = TransparentNamed {
        value: String::from("raw-secret"),
    };
    let redactor = Redactor::standard();
    check_transparent_tokens(&source, serde_test::Token::Str("<redacted>"));
    check_transparent_tokens(&redactor.redact_view(&source), serde_test::Token::Str("<redacted>"));

    let disabled = Redactor::new(RedactionPolicy::disabled());
    check_transparent_tokens(&disabled.redact_view(&source), serde_test::Token::Str("raw-secret"));
    assert_eq!(
        serde_json::to_value(redactor.redact_view(&source)).expect("transparent JSON should serialize"),
        serde_json::json!("<redacted>")
    );
    assert_eq!(
        serde_json::to_value(disabled.redact_view(&source)).expect("disabled transparent JSON should serialize"),
        serde_json::json!("raw-secret")
    );
}

#[test]
fn test_transparent_skip_serializing_if_is_ignored_for_named_and_tuple_fields() {
    use serde_test::Token;

    TRANSPARENT_PREDICATE_CALLS.with(|calls| calls.set(0));
    let named = ConditionalNamed { value: String::new() };
    let named_source = NativeConditionalNamed { value: String::new() };
    let tuple = ConditionalTuple(String::new());
    let tuple_source = NativeConditionalTuple(String::new());
    let standard = Redactor::standard();
    let disabled = Redactor::new(RedactionPolicy::disabled());

    check_transparent_tokens(&named_source, Token::Str(""));
    check_transparent_tokens(&named, Token::Str(""));
    check_transparent_tokens(&standard.redact_view(&named), Token::Str(""));
    check_transparent_tokens(&disabled.redact_view(&named), Token::Str(""));
    check_transparent_tokens(&tuple_source, Token::Str(""));
    check_transparent_tokens(&tuple, Token::Str(""));
    check_transparent_tokens(&standard.redact_view(&tuple), Token::Str(""));
    check_transparent_tokens(&disabled.redact_view(&tuple), Token::Str(""));
    assert_eq!(TRANSPARENT_PREDICATE_CALLS.with(std::cell::Cell::get), 0);

    let ordinary = OrdinaryConditional { value: String::new() };
    serde_test::assert_ser_tokens(
        &ordinary,
        &[
            Token::Struct {
                name: "OrdinaryConditional",
                len: 0,
            },
            Token::StructEnd,
        ],
    );
    assert!(TRANSPARENT_PREDICATE_CALLS.with(std::cell::Cell::get) > 0);

    let skipped = TransparentSkipped(String::from("raw-secret"));
    serde_test::assert_ser_tokens(
        &standard.redact_view(&skipped),
        &[Token::UnitStruct {
            name: "TransparentSkipped",
        }],
    );
    check_transparent_tokens(&disabled.redact_view(&skipped), Token::Str("raw-secret"));

    #[cfg(feature = "json")]
    {
        assert_eq!(serde_json::to_value(&named_source).unwrap(), serde_json::json!(""));
        assert_eq!(
            serde_json::to_value(standard.redact_view(&named)).unwrap(),
            serde_json::json!("")
        );
        assert_eq!(
            serde_json::to_value(disabled.redact_view(&named)).unwrap(),
            serde_json::json!("")
        );
        assert_eq!(serde_json::to_value(&named).unwrap(), serde_json::json!(""));
        assert_eq!(serde_json::to_value(&tuple_source).unwrap(), serde_json::json!(""));
        assert_eq!(
            serde_json::to_value(standard.redact_view(&tuple)).unwrap(),
            serde_json::json!("")
        );
        assert_eq!(
            serde_json::to_value(disabled.redact_view(&tuple)).unwrap(),
            serde_json::json!("")
        );
        assert_eq!(serde_json::to_value(&tuple).unwrap(), serde_json::json!(""));
    }
}

#[test]
fn test_ordinary_newtype_ignores_serde_skip_predicate() {
    use serde_test::Token;

    for input in ["", "visible"] {
        let native = NativeConditionalNewtype(input.to_owned());
        let source = ConditionalNewtype(input.to_owned());
        let tokens = [
            Token::NewtypeStruct { name: "ConditionalNewtype" },
            Token::Str(input),
        ];
        TRANSPARENT_PREDICATE_CALLS.with(|calls| calls.set(0));
        serde_test::assert_ser_tokens(&native, &tokens);
        serde_test::assert_ser_tokens(&source, &tokens);
        for policy in [RedactionPolicy::standard(), RedactionPolicy::disabled()] {
            let redactor = Redactor::new(policy);
            serde_test::assert_ser_tokens(&redactor.redact_view(&source), &tokens);
        }
        assert_eq!(TRANSPARENT_PREDICATE_CALLS.with(std::cell::Cell::get), 0);
    }

    let adapted = AdaptedNewtype(String::new());
    serde_test::assert_ser_tokens(
        &adapted,
        &[Token::NewtypeStruct { name: "AdaptedNewtype" }, Token::Str("")],
    );
    let standard = Redactor::standard();
    let skipped = SkippedNewtype(String::from("private"));
    TRANSPARENT_PREDICATE_CALLS.with(|calls| calls.set(0));
    serde_test::assert_ser_tokens(
        &standard.redact_view(&skipped),
        &[Token::UnitStruct { name: "SkippedNewtype" }],
    );
    assert_eq!(TRANSPARENT_PREDICATE_CALLS.with(std::cell::Cell::get), 0);
    serde_test::assert_ser_tokens(
        &Redactor::new(RedactionPolicy::disabled()).redact_view(&skipped),
        &[Token::NewtypeStruct { name: "SkippedNewtype" }, Token::Str("private")],
    );
    assert_eq!(TRANSPARENT_PREDICATE_CALLS.with(std::cell::Cell::get), 0);
    let secret = OrdinaryNewtype(String::from("secret-value"));
    serde_test::assert_ser_tokens(
        &standard.redact_view(&secret),
        &[Token::NewtypeStruct { name: "OrdinaryNewtype" }, Token::Str("<redacted>")],
    );
    #[cfg(feature = "json")]
    {
        assert_eq!(serde_json::to_string(&NativeConditionalNewtype(String::new())).unwrap(), "\"\"");
        assert_eq!(standard.to_json(&ConditionalNewtype(String::new())).unwrap(), "\"\"");
    }
}

#[test]
fn test_conditional_skip_field_emits_serde_event_for_named_struct_and_variant() {
    fn observed<T: Serialize>(value: &T) -> (Vec<(&'static str, &'static str)>, Vec<usize>) {
        let mut events = Vec::new();
        let mut counts = Vec::new();
        value.serialize(&mut VariantIndexProbe::new(&mut events, &mut counts, false, None)).unwrap();
        (events, counts)
    }
    let struct_value = || NativeConditionalSkipStruct {
        optional: String::new(), visible: String::from("visible"), never: String::new(),
    };
    let struct_source = || ConditionalSkipStruct {
        optional: String::new(), visible: String::from("visible"), never: String::new(),
    };
    let variant_value = || NativeConditionalSkipEvent::Payload {
        optional: String::new(), visible: String::from("visible"), never: String::new(),
    };
    let variant_source = || ConditionalSkipEvent::Payload {
        optional: String::new(), visible: String::from("visible"), never: String::new(),
    };
    let expected_struct = vec![("begin", "ConditionalSkipStruct"), ("skip", "wire_optional"), ("field", "visible"), ("end", "")];
    let expected_variant = vec![("begin", "payload"), ("skip", "wire_optional"), ("field", "visible"), ("end", "")];
    let native_struct = struct_value();
    let source_struct = struct_source();
    let native_variant = variant_value();
    let source_variant = variant_source();
    let redactor = Redactor::standard();
    for (actual, expected) in [
        (observed(&native_struct), expected_struct.clone()),
        (observed(&source_struct), expected_struct.clone()),
        (observed(&redactor.redact_view(&source_struct)), expected_struct),
        (observed(&native_variant), expected_variant.clone()),
        (observed(&source_variant), expected_variant.clone()),
        (observed(&redactor.redact_view(&source_variant)), expected_variant),
    ] {
        assert_eq!(actual.0, expected);
        assert_eq!(actual.1, vec![1]);
    }
}

#[test]
fn test_conditional_skip_field_redact_skip_predicate_scope_and_errors() {
    let source = ConditionalSkipStruct {
        optional: String::new(), visible: String::from("yes"), never: String::new(),
    };
    let mut source_events = Vec::new();
    let mut source_counts = Vec::new();
    let source_result = source.serialize(&mut VariantIndexProbe::new(
        &mut source_events, &mut source_counts, true, None,
    ));
    assert!(matches!(source_result, Err(ProbeError)));
    assert!(source_events.contains(&("skip", "wire_optional")));
    assert!(serde_json::to_string(&source).is_ok(), "failed source serialization must release its scope");

    let value = RedactSkipConditional { optional: String::new(), visible: String::from("yes") };
    TRANSPARENT_PREDICATE_CALLS.with(|calls| calls.set(0));
    let mut events = Vec::new(); let mut counts = Vec::new();
    Redactor::standard().redact_view(&value)
        .serialize(&mut VariantIndexProbe::new(&mut events, &mut counts, false, None)).unwrap();
    assert_eq!(events, vec![("begin", "RedactSkipConditional"), ("field", "visible"), ("end", "")]);
    assert_eq!(TRANSPARENT_PREDICATE_CALLS.with(std::cell::Cell::get), 0);

    let mut events = Vec::new(); let mut counts = Vec::new();
    Redactor::new(RedactionPolicy::disabled()).redact_view(&value)
        .serialize(&mut VariantIndexProbe::new(&mut events, &mut counts, false, None)).unwrap();
    assert_eq!(events, vec![("begin", "RedactSkipConditional"), ("skip", "wire_optional"), ("field", "visible"), ("end", "")]);
    assert_eq!(TRANSPARENT_PREDICATE_CALLS.with(std::cell::Cell::get), 1);

    let mut events = Vec::new(); let mut counts = Vec::new();
    let result = Redactor::new(RedactionPolicy::disabled()).redact_view(&value)
        .serialize(&mut VariantIndexProbe::new(&mut events, &mut counts, true, None));
    assert!(matches!(result, Err(ProbeError)));
    assert!(events.contains(&("skip", "wire_optional")));
    assert!(serde_json::to_string(&Redactor::standard().redact_view(&value)).is_ok(), "failed serialization must release its scope");
}

#[test]
fn test_transparent_tuple_and_ordinary_newtype_keep_distinct_events() {
    let transparent = TransparentTuple(String::from("raw-secret"));
    let ordinary = OrdinaryNewtype(String::from("raw-secret"));
    let redactor = Redactor::standard();
    check_transparent_tokens(
        &redactor.redact_view(&transparent),
        serde_test::Token::Str("<redacted>"),
    );
    serde_test::assert_ser_tokens(
        &ordinary,
        &[
            serde_test::Token::NewtypeStruct {
                name: "OrdinaryNewtype",
            },
            serde_test::Token::Str("<redacted>"),
        ],
    );
}

#[test]
fn test_transparent_forwarding_retains_payload_limit() {
    let source = TransparentTuple(String::from("raw-secret"));
    let payload_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_serde_payload_bytes(1);
        })
        .expect("payload limits should be valid")
        .build()
        .expect("payload policy should be valid");
    let payload_result = serde_json::to_string(&Redactor::new(payload_policy).redact_view(&source));
    assert!(
        payload_result.is_err(),
        "transparent serialization must honor payload limits"
    );
}

#[test]
fn test_transparent_forwarding_retains_node_limit() {
    let source = TransparentBudget(NestedBudget {
        first: String::from("first"),
        second: String::from("second"),
    });
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1);
        })
        .expect("node limits should be valid")
        .build()
        .expect("node policy should be valid");
    let result = serde_json::to_string(&Redactor::new(policy).redact_view(&source));
    assert_eq!(
        result.expect("node exhaustion should use the safe mask"),
        "\"<redacted>\""
    );
}

#[test]
fn test_adjacent_tags_use_unit_variant_events_with_effective_names() {
    use serde_test::Token;

    let redactor = Redactor::standard();
    let unit = AdjacentEvent::Unit;
    serde_test::assert_ser_tokens(
        &redactor.redact_view(&unit),
        &[
            Token::Struct {
                name: "WireEvent",
                len: 1,
            },
            Token::Str("kind"),
            Token::UnitVariant {
                name: "WireEvent",
                variant: "unit",
            },
            Token::StructEnd,
        ],
    );

    for (value, variant) in [
        (AdjacentEvent::Tuple(String::from("x")), "tuple"),
        (AdjacentEvent::Newtype(String::from("x")), "newtype"),
    ] {
        serde_test::assert_ser_tokens(
            &redactor.redact_view(&value),
            &[
                Token::Struct {
                    name: "WireEvent",
                    len: 2,
                },
                Token::Str("kind"),
                Token::UnitVariant {
                    name: "WireEvent",
                    variant,
                },
                Token::Str("payload"),
                Token::Str("<redacted>"),
                Token::StructEnd,
            ],
        );
    }

    let named = AdjacentEvent::Named {
        secret: String::from("x"),
    };
    let named_tokens = [
        Token::Struct {
            name: "WireEvent",
            len: 2,
        },
        Token::Str("kind"),
        Token::UnitVariant {
            name: "WireEvent",
            variant: "wire-name",
        },
        Token::Str("payload"),
        Token::Struct {
            name: "wire-name",
            len: 1,
        },
        Token::Str("secret"),
        Token::Str("<redacted>"),
        Token::StructEnd,
        Token::StructEnd,
    ];
    serde_test::assert_ser_tokens(&redactor.redact_view(&named), &named_tokens);
    serde_test::assert_ser_tokens(&named, &named_tokens);
    let disabled = Redactor::new(RedactionPolicy::disabled());
    serde_test::assert_ser_tokens(
        &disabled.redact_view(&named),
        &[
            Token::Struct {
                name: "WireEvent",
                len: 2,
            },
            Token::Str("kind"),
            Token::UnitVariant {
                name: "WireEvent",
                variant: "wire-name",
            },
            Token::Str("payload"),
            Token::Struct {
                name: "wire-name",
                len: 1,
            },
            Token::Str("secret"),
            Token::Str("x"),
            Token::StructEnd,
            Token::StructEnd,
        ],
    );
    let json = serde_json::to_value(redactor.redact_view(&named)).expect("adjacent JSON should serialize");
    assert_eq!(
        json,
        serde_json::json!({ "kind": "wire-name", "payload": { "secret": "<redacted>" } })
    );

    let empty = AdjacentEvent::Empty {};
    serde_test::assert_ser_tokens(
        &redactor.redact_view(&empty),
        &[
            Token::Struct {
                name: "WireEvent",
                len: 2,
            },
            Token::Str("kind"),
            Token::UnitVariant {
                name: "WireEvent",
                variant: "empty",
            },
            Token::Str("payload"),
            Token::Struct { name: "empty", len: 0 },
            Token::StructEnd,
            Token::StructEnd,
        ],
    );

    let raw = AdjacentEvent::r#type {
        secret: String::from("x"),
    };
    serde_test::assert_ser_tokens(
        &redactor.redact_view(&raw),
        &[
            Token::Struct {
                name: "WireEvent",
                len: 2,
            },
            Token::Str("kind"),
            Token::UnitVariant {
                name: "WireEvent",
                variant: "type",
            },
            Token::Str("payload"),
            Token::Struct { name: "type", len: 1 },
            Token::Str("secret"),
            Token::Str("<redacted>"),
            Token::StructEnd,
            Token::StructEnd,
        ],
    );
}

#[test]
fn test_adjacent_tag_probe_preserves_enum_index_for_each_shape() {
    use std::cell::Cell;

    let variants = [
        (AdjacentEvent::Unit, 0),
        (AdjacentEvent::Tuple(String::from("x")), 1),
        (AdjacentEvent::Newtype(String::from("x")), 2),
        (
            AdjacentEvent::Named {
                secret: String::from("x"),
            },
            3,
        ),
    ];
    for (value, index) in variants {
        let recorded = Cell::new(None);
        let mut events = Vec::new();
        let mut field_counts = Vec::new();
        let mut serializer = VariantIndexProbe::new(&mut events, &mut field_counts, false, Some(&recorded));
        Redactor::standard()
            .redact_view(&value)
            .serialize(&mut serializer)
            .expect("the probe serializer accepts the adjacent event");
        assert_eq!(
            recorded.get(),
            Some((
                "WireEvent",
                index,
                match index {
                    0 => "unit",
                    1 => "tuple",
                    2 => "newtype",
                    _ => "wire-name",
                }
            ))
        );
    }
}

#[test]
fn test_adjacent_tag_adapter_does_not_shadow_user_type_parameters() {
    let value: GenericAdjacent<String> = GenericAdjacent::Data(String::from("value"));
    serde_test::assert_ser_tokens(
        &Redactor::standard().redact_view(&value),
        &[
            serde_test::Token::Struct {
                name: "GenericAdjacent",
                len: 2,
            },
            serde_test::Token::Str("kind"),
            serde_test::Token::UnitVariant {
                name: "GenericAdjacent",
                variant: "Data",
            },
            serde_test::Token::Str("payload"),
            serde_test::Token::Str("value"),
            serde_test::Token::StructEnd,
        ],
    );
}

#[test]
fn test_adjacent_tag_still_obeys_payload_budget() {
    for budget in [0, 3, 4] {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_serde_payload_bytes(budget);
            })
            .expect("limits should be valid")
            .build()
            .expect("policy should be valid");
        let redactor = Redactor::new(policy);
        let result = serde_json::to_string(&redactor.redact_view(&AdjacentEvent::Unit));
        if budget < 4 {
            assert!(result.is_err(), "tag must exceed payload budget {budget}");
        } else {
            assert_eq!(result.expect("four-byte tag fits"), r#"{"kind":"unit"}"#);
        }
    }
}

#[test]
fn test_untagged_named_variant_uses_container_name() {
    let value = UntaggedEvent::Named {
        secret: String::from("raw-secret"),
    };
    serde_test::assert_ser_tokens(
        &Redactor::standard().redact_view(&value),
        &[
            serde_test::Token::Struct {
                name: "WireEvent",
                len: 1,
            },
            serde_test::Token::Str("secret"),
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::StructEnd,
        ],
    );
}

struct ProbeError;

impl std::fmt::Debug for ProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("probe serializer error")
    }
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("probe serializer error")
    }
}

impl std::error::Error for ProbeError {}

impl serde::ser::Error for ProbeError {
    fn custom<T: std::fmt::Display>(_message: T) -> Self {
        Self
    }
}

struct VariantIndexProbe<'a> {
    events: &'a mut Vec<(&'static str, &'static str)>,
    field_counts: &'a mut Vec<usize>,
    fail_on_skip: bool,
    recorded: Option<&'a std::cell::Cell<Option<(&'static str, u32, &'static str)>>>,
}

impl<'a> VariantIndexProbe<'a> {
    fn new(
        events: &'a mut Vec<(&'static str, &'static str)>,
        field_counts: &'a mut Vec<usize>,
        fail_on_skip: bool,
        recorded: Option<&'a std::cell::Cell<Option<(&'static str, u32, &'static str)>>>,
    ) -> Self {
        Self { events, field_counts, fail_on_skip, recorded }
    }
}

struct ProbeStruct<'probe, 'a> {
    probe: &'probe mut VariantIndexProbe<'a>,
}

impl serde::ser::SerializeStruct for ProbeStruct<'_, '_> {
    type Ok = ();
    type Error = ProbeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error> {
        self.probe.events.push(("field", key));
        value.serialize(&mut *self.probe)
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.probe.events.push(("skip", key));
        if self.probe.fail_on_skip { Err(ProbeError) } else { Ok(()) }
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.probe.events.push(("end", ""));
        Ok(())
    }
}

impl serde::ser::SerializeStructVariant for ProbeStruct<'_, '_> {
    type Ok = ();
    type Error = ProbeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error> {
        self.probe.events.push(("field", key));
        value.serialize(&mut *self.probe)
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.probe.events.push(("skip", key));
        if self.probe.fail_on_skip { Err(ProbeError) } else { Ok(()) }
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.probe.events.push(("end", ""));
        Ok(())
    }
}

impl<'probe, 'a> serde::Serializer for &'probe mut VariantIndexProbe<'a> {
    type Ok = ();
    type Error = ProbeError;
    type SerializeSeq = serde::ser::Impossible<(), ProbeError>;
    type SerializeTuple = serde::ser::Impossible<(), ProbeError>;
    type SerializeTupleStruct = serde::ser::Impossible<(), ProbeError>;
    type SerializeTupleVariant = serde::ser::Impossible<(), ProbeError>;
    type SerializeMap = serde::ser::Impossible<(), ProbeError>;
    type SerializeStruct = ProbeStruct<'probe, 'a>;
    type SerializeStructVariant = ProbeStruct<'probe, 'a>;

    fn serialize_bool(self, _value: bool) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_i8(self, _value: i8) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_i16(self, _value: i16) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_i32(self, _value: i32) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_i64(self, _value: i64) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_i128(self, _value: i128) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_u8(self, _value: u8) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_u16(self, _value: u16) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_u32(self, _value: u32) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_u64(self, _value: u64) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_u128(self, _value: u128) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_f32(self, _value: f32) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_f64(self, _value: f64) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_char(self, _value: char) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_str(self, _value: &str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        if let Some(recorded) = self.recorded { recorded.set(Some((name, index, variant))); }
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(serde::ser::Error::custom("sequence unsupported"))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(serde::ser::Error::custom("tuple unsupported"))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(serde::ser::Error::custom("tuple struct unsupported"))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(serde::ser::Error::custom("tuple variant unsupported"))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(serde::ser::Error::custom("map unsupported"))
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct, Self::Error> {
        self.events.push(("begin", _name));
        self.field_counts.push(_len);
        Ok(ProbeStruct { probe: self })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.events.push(("begin", _variant));
        self.field_counts.push(_len);
        Ok(ProbeStruct { probe: self })
    }
}
