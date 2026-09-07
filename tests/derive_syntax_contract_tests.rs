// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public derive syntax contracts shared with ordinary Serde field controls.

#![cfg(all(feature = "derive", feature = "serde"))]

use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::marker::PhantomData;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use serde::Serializer;
use serde_json::json;
use serde_json::to_value;

/// Bare Serde omission controls remain composable with later field attributes.
#[test]
fn test_serde_bare_skip_can_precede_another_field_control() {
    #[derive(Debug, Redact)]
    struct Record {
        #[serde(skip, default)]
        hidden: String,
        #[serde(skip_serializing, rename = "omitted")]
        also_hidden: String,
        visible: u32,
    }

    let record = Record {
        hidden: "secret-one".to_owned(),
        also_hidden: "secret-two".to_owned(),
        visible: 7,
    };
    for redactor in [Redactor::standard(), Redactor::new(RedactionPolicy::disabled())] {
        let encoded = to_value(redactor.redact_view(&record)).expect("serialize supported combined controls");
        assert_eq!(encoded, json!({"visible": 7}));
    }
}

/// Generated projection lifetimes must remain distinct from legal source names.
#[test]
fn test_projection_lifetimes_do_not_shadow_source_lifetimes() {
    #[derive(Redact)]
    #[redact(serde)]
    struct Borrowed<'__qubit_redact, '__qubit_redact_policy, '__qubit_redact_lifetime, '__qubit_redact_lifetime_0> {
        first: &'__qubit_redact str,
        second: &'__qubit_redact_policy str,
        third: &'__qubit_redact_lifetime str,
        fourth: &'__qubit_redact_lifetime_0 str,
    }

    let first = String::from("one");
    let second = String::from("two");
    let third = String::from("three");
    let fourth = String::from("four");
    let value = Borrowed {
        first: &first,
        second: &second,
        third: &third,
        fourth: &fourth,
    };
    let expected = json!({"first": "one", "second": "two", "third": "three", "fourth": "four"});

    assert_eq!(
        to_value(Redactor::standard().redact_view(&value)).expect("borrowed projection"),
        expected
    );
    assert_eq!(to_value(&value).expect("derived source serialization"), expected);
}

/// Predicates retain concrete generic field shapes without requiring source
/// Serialize.
#[test]
fn test_generic_skip_predicate_preserves_projection_type_parameters() {
    #[derive(Redact)]
    struct Generic<T: Debug> {
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<T>,
    }

    let redactor = Redactor::standard();
    assert_eq!(
        to_value(redactor.redact_view(&Generic { value: Some(7u32) })).expect("generic Some"),
        json!({"value": 7})
    );
    assert_eq!(
        to_value(redactor.redact_view(&Generic::<u32> { value: None })).expect("generic None"),
        json!({})
    );

    #[derive(Debug)]
    struct TextOnly;

    let text_only = Generic { value: Some(TextOnly) };
    assert!(format!("{}", redactor.redact_view(&text_only)).contains("TextOnly"));
}

/// Borrowed nested projections keep source lifetimes separate from capability
/// bounds.
#[test]
fn test_generic_projection_preserves_borrowed_nested_fields() {
    #[derive(Redact)]
    #[redact(serde)]
    struct Child<'a> {
        name: &'a str,
    }

    #[derive(Redact)]
    struct Parent<'a> {
        #[redact(nested)]
        child: Child<'a>,
    }

    let name = String::from("ada");
    let value = Parent {
        child: Child { name: &name },
    };
    assert_eq!(
        to_value(Redactor::standard().redact_view(&value)).expect("borrowed nested projection"),
        json!({"child": {"name": "ada"}})
    );
}

/// Custom adapters may serialize generic values that do not implement
/// Serialize.
#[test]
fn test_generic_custom_adapter_keeps_its_source_bounds() {
    fn serialize_as_text<T: Display, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    #[derive(Debug)]
    struct TextOnly;

    impl Display for TextOnly {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
            formatter.write_str("custom")
        }
    }

    #[derive(Redact)]
    struct Generic<T: Debug + Display> {
        #[serde(serialize_with = "serialize_as_text")]
        value: T,
    }

    let value = Generic { value: TextOnly };
    assert_eq!(
        to_value(Redactor::standard().redact_view(&value)).expect("generic adapter"),
        json!({"value": "custom"})
    );
}

/// Predicates work in tuple and enum fields with the same concrete generic
/// shape.
#[test]
fn test_generic_predicates_cover_tuple_and_enum_projections() {
    #[derive(Redact)]
    struct Tuple<T: Debug>(#[serde(skip_serializing_if = "Option::is_none")] Option<T>, u32);

    #[derive(Redact)]
    enum Event<T: Debug> {
        Named {
            #[serde(skip_serializing_if = "Option::is_none")]
            value: Option<T>,
        },
        Tuple(#[serde(skip_serializing_if = "Option::is_none")] Option<T>, u32),
    }

    let redactor = Redactor::standard();
    assert_eq!(
        to_value(redactor.redact_view(&Tuple(Some(7u32), 9))).expect("tuple Some"),
        json!([7, 9])
    );
    assert_eq!(
        to_value(redactor.redact_view(&Tuple::<u32>(None, 9))).expect("tuple None"),
        json!([9])
    );
    assert_eq!(
        to_value(redactor.redact_view(&Event::Named { value: Some(7u32) })).expect("named enum"),
        json!({"Named": {"value": 7}})
    );
    assert_eq!(
        to_value(redactor.redact_view(&Event::<u32>::Tuple(None, 9))).expect("tuple enum"),
        json!({"Tuple": [9]})
    );
}

/// Serde defaults keep concrete nested Option and Vec projection bounds.
#[test]
fn test_serde_defaults_preserve_nested_option_and_vec_capabilities() {
    #[derive(Debug, Redact)]
    #[redact(serde)]
    struct Child {
        value: String,
    }

    #[derive(Redact)]
    #[redact(serde)]
    struct Envelope {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        child: Option<Child>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        children: Vec<Child>,
    }

    let encoded = to_value(Redactor::standard().redact_view(&Envelope {
        child: Some(Child { value: "ok".to_owned() }),
        children: vec![Child {
            value: "also-ok".to_owned(),
        }],
    }))
    .expect("serde defaults with nested capabilities");
    assert_eq!(
        encoded,
        json!({"child": {"value": "ok"}, "children": [{"value": "also-ok"}]})
    );
}

/// Source defaults and const parameters do not leak into generated impl
/// defaults.
#[test]
fn test_generic_projection_retains_const_parameters_and_defaults() {
    #[derive(Redact)]
    struct Generic<T: Debug = u32, const N: usize = 2> {
        #[serde(skip_serializing_if = "Option::is_none")]
        values: Option<[T; N]>,
    }

    let value = Generic {
        values: Some([1u32, 2]),
    };
    assert_eq!(
        to_value(Redactor::standard().redact_view(&value)).expect("const generic projection"),
        json!({"values": [1, 2]})
    );
}

/// User fields and variants cannot collide with projection-only marker names.
#[allow(non_camel_case_types)]
#[test]
fn test_projection_markers_do_not_collide_with_source_members() {
    #[derive(Redact)]
    struct Record {
        r#__qubit_redact_lifetime: String,
        __qubit_redact_lifetime_0: u32,
    }
    #[allow(non_camel_case_types)]
    #[derive(Redact)]
    enum Event {
        __QubitRedactLifetime,
        __QubitRedactLifetime_0,
    }
    let redactor = Redactor::standard();
    let value = Record {
        __qubit_redact_lifetime: "visible".to_owned(),
        __qubit_redact_lifetime_0: 7,
    };
    assert_eq!(
        to_value(redactor.redact_view(&value)).expect("marker field"),
        json!({"__qubit_redact_lifetime": "visible", "__qubit_redact_lifetime_0": 7})
    );
    assert_eq!(
        to_value(redactor.redact_view(&Event::__QubitRedactLifetime)).expect("marker variant"),
        json!("__QubitRedactLifetime")
    );
    assert_eq!(
        to_value(redactor.redact_view(&Event::__QubitRedactLifetime_0)).expect("marker suffix"),
        json!("__QubitRedactLifetime_0")
    );
}

/// Adapter helper items retain lifetimes referenced only by inline bounds.
#[test]
fn test_adapter_helper_retains_inline_lifetime_dependencies() {
    fn as_text<T: Display, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }
    #[derive(Redact)]
    struct Borrowed<'a, 'b: 'a, T: Debug + Display + 'b> {
        #[serde(serialize_with = "as_text")]
        value: T,
        first: &'a str,
        second: &'b str,
    }
    let first = String::from("one");
    let second = String::from("two");
    let value = Borrowed {
        value: 7u32,
        first: &first,
        second: &second,
    };
    assert_eq!(
        to_value(Redactor::standard().redact_view(&value)).expect("inline lifetime bounds"),
        json!({"value": "7", "first": "one", "second": "two"})
    );
}

/// Custom adapter carriers preserve source where-clause bounds.
#[test]
fn test_adapter_helper_preserves_where_clause_bounds() {
    fn as_text<T: Display, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }
    #[derive(Redact)]
    struct Value<T>
    where
        T: Debug + Display,
    {
        #[serde(serialize_with = "as_text")]
        value: T,
    }
    assert_eq!(
        to_value(Redactor::standard().redact_view(&Value { value: 7u32 })).expect("adapter where clause"),
        json!({"value": "7"})
    );
}

/// Adapter carriers retain source type arguments that cannot be inferred from
/// the field.
#[test]
fn test_adapter_helper_preserves_indirect_type_arguments() {
    fn as_text<T: Display, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }
    #[derive(Redact)]
    struct Value<T, U: ?Sized>
    where
        T: Debug + Display + AsRef<U> + AsRef<str>,
        U: Debug,
    {
        #[serde(serialize_with = "as_text")]
        value: T,
        marker: PhantomData<U>,
    }
    let value = Value::<String, str> {
        value: "visible".to_owned(),
        marker: PhantomData,
    };
    assert_eq!(
        to_value(Redactor::standard().redact_view(&value)).expect("indirect adapter type argument"),
        json!({"value": "visible", "marker": null})
    );
}

/// Unconditionally omitted fields need no Serde capability, including generic
/// fields.
#[test]
fn test_serde_skipped_fields_need_no_serialize_capability() {
    #[derive(Debug)]
    struct TextOnly;
    #[derive(Redact)]
    #[redact(serde)]
    struct Record<T: Debug> {
        #[serde(skip)]
        hidden: T,
        #[serde(skip_serializing)]
        also_hidden: TextOnly,
        visible: u32,
    }
    #[derive(Redact)]
    #[redact(serde)]
    struct Tuple<T: Debug>(#[serde(skip_serializing)] T, u32);
    let record = Record {
        hidden: TextOnly,
        also_hidden: TextOnly,
        visible: 7,
    };
    let tuple = Tuple(TextOnly, 9);
    assert_eq!(
        to_value(&record).expect("source skips non-serializable fields"),
        json!({"visible": 7})
    );
    assert_eq!(to_value(&tuple).expect("source skips tuple field"), json!([9]));
    for redactor in [Redactor::standard(), Redactor::new(RedactionPolicy::disabled())] {
        assert_eq!(
            to_value(redactor.redact_view(&record)).expect("projection skips fields"),
            json!({"visible": 7})
        );
        assert_eq!(
            to_value(redactor.redact_view(&tuple)).expect("projection skips tuple field"),
            json!([9])
        );
    }
}

/// Skipped variants do not impose serialization bounds on their unreachable
/// payload.
#[test]
fn test_serde_skipped_variants_need_no_serialize_capability() {
    #[derive(Debug)]
    struct TextOnly;
    #[derive(Redact)]
    #[redact(serde)]
    enum Event<T: Debug> {
        #[serde(skip)]
        Hidden(T),
        Visible(u32),
    }
    let visible = Event::<TextOnly>::Visible(7);
    assert_eq!(
        to_value(&visible).expect("serialize visible variant"),
        json!({"Visible": 7})
    );
    let hidden = Event::Hidden(TextOnly);
    for redactor in [Redactor::standard(), Redactor::new(RedactionPolicy::disabled())] {
        assert_eq!(
            to_value(redactor.redact_view(&visible)).expect("visible projection"),
            json!({"Visible": 7})
        );
        assert!(to_value(redactor.redact_view(&hidden)).is_err());
    }
}

/// Nested optional and sequence projections retain actual non-static source
/// borrows.
#[test]
fn test_nested_container_projections_accept_borrowed_children() {
    #[derive(Redact)]
    #[redact(serde)]
    struct Child<'a> {
        name: &'a str,
    }
    #[derive(Redact)]
    struct Record<'a> {
        #[redact(nested)]
        optional: Option<Child<'a>>,
        #[redact(nested)]
        children: Vec<Child<'a>>,
    }
    let name = String::from("borrowed");
    let value = Record {
        optional: Some(Child { name: &name }),
        children: vec![Child { name: &name }],
    };
    assert_eq!(
        to_value(Redactor::standard().redact_view(&value)).expect("borrowed container children"),
        json!({"optional": {"name": "borrowed"}, "children": [{"name": "borrowed"}]}),
    );
}

/// Generic source serialization uses the same nested projection capability as
/// explicit views, including children that borrow local data.
#[test]
fn test_generic_source_serde_accepts_nested_projection_children() {
    #[derive(Redact)]
    #[redact(serde)]
    struct Child<'a> {
        name: &'a str,
    }
    #[derive(Redact)]
    #[redact(serde)]
    struct Record<T> {
        #[redact(nested)]
        child: T,
    }
    #[derive(Redact)]
    #[redact(serde)]
    struct Tuple<T>(#[redact(nested)] T);
    #[derive(Redact)]
    #[redact(serde)]
    enum Event<T> {
        Named {
            #[redact(nested)]
            child: T,
        },
        Tuple(#[redact(nested)] T),
    }
    let name = String::from("borrowed");
    let record = Record {
        child: Child { name: &name },
    };
    let tuple = Tuple(Child { name: &name });
    let optional = Record {
        child: Some(Child { name: &name }),
    };
    let vector = Record {
        child: vec![Child { name: &name }],
    };
    let recursive = Record {
        child: Record {
            child: Child { name: &name },
        },
    };
    let named = Event::Named {
        child: Child { name: &name },
    };
    let event_tuple = Event::Tuple(Child { name: &name });
    assert_eq!(
        to_value(&optional).expect("generic optional child"),
        json!({"child": {"name": "borrowed"}})
    );
    assert_eq!(
        to_value(&vector).expect("generic vector child"),
        json!({"child": [{"name": "borrowed"}]})
    );
    assert_eq!(
        to_value(&recursive).expect("recursive generic child"),
        json!({"child": {"child": {"name": "borrowed"}}})
    );
    assert_eq!(
        to_value(&named).expect("generic named variant"),
        json!({"Named": {"child": {"name": "borrowed"}}})
    );
    assert_eq!(
        to_value(&event_tuple).expect("generic tuple variant"),
        json!({"Tuple": {"name": "borrowed"}})
    );
    assert_eq!(
        to_value(&record).expect("nested generic source"),
        json!({"child": {"name": "borrowed"}})
    );
    assert_eq!(
        to_value(&tuple).expect("nested generic tuple"),
        json!({"name": "borrowed"})
    );
    assert_eq!(
        to_value(Redactor::standard().redact_view(&record)).expect("nested generic view"),
        json!({"child": {"name": "borrowed"}})
    );
}
