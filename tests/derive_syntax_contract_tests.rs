// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public derive syntax contracts shared with ordinary Serde field controls.

#![cfg(all(feature = "derive", feature = "serde"))]

use std::cell::Cell;
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

thread_local! {
    static SELF_PREDICATE_CALLS: Cell<usize> = const { Cell::new(0) };
}

fn is_empty_string(value: &str) -> bool {
    SELF_PREDICATE_CALLS.with(|calls| calls.set(calls.get() + 1));
    value.is_empty()
}

/// Recursive predicates bind `Self` to the source type and run only at
/// serialization.
#[test]
fn test_recursive_self_predicate_is_rebound_and_lazy() {
    #[derive(Debug, Redact)]
    #[redact(serde)]
    struct Node {
        #[serde(skip_serializing_if = "Self::is_empty")]
        label: String,
        next: Option<Box<Node>>,
    }

    impl Node {
        #[allow(clippy::ptr_arg)] // Serde skip predicates take the field's exact type.
        fn is_empty(value: &String) -> bool {
            is_empty_string(value)
        }
    }

    let redactor = Redactor::standard();
    let node = Node {
        label: String::new(),
        next: Some(Box::new(Node {
            label: String::new(),
            next: None,
        })),
    };
    SELF_PREDICATE_CALLS.with(|calls| calls.set(0));
    let view = redactor.redact_view(&node);
    assert_eq!(SELF_PREDICATE_CALLS.with(Cell::get), 0);
    assert_eq!(
        to_value(view).expect("recursive view omits empty labels"),
        json!({"next": {"next": null}})
    );
    assert_eq!(SELF_PREDICATE_CALLS.with(Cell::get), 2);
    assert_eq!(
        to_value(&node).expect("source serialization omits empty labels"),
        json!({"next": {"next": null}})
    );
    assert_eq!(SELF_PREDICATE_CALLS.with(Cell::get), 4);

    let nonempty = Node {
        label: "kept".to_owned(),
        next: None,
    };
    assert_eq!(
        to_value(redactor.redact_view(&nonempty)).expect("non-empty label remains"),
        json!({"label": "kept", "next": null})
    );
}

/// Recursive enum predicates work for named and tuple fields.
#[test]
fn test_recursive_enum_self_predicates_cover_named_and_tuple_fields() {
    #[derive(Debug, Redact)]
    enum Tree {
        Named {
            #[serde(skip_serializing_if = "Self::empty")]
            label: String,
            child: Option<Box<Tree>>,
        },
        Tuple(#[serde(skip_serializing_if = "Self::empty")] String, Option<Box<Tree>>),
    }

    impl Tree {
        #[allow(clippy::ptr_arg)] // Serde skip predicates take the field's exact type.
        fn empty(value: &String) -> bool {
            value.is_empty()
        }
    }

    let redactor = Redactor::standard();
    let named = Tree::Named {
        label: String::new(),
        child: None,
    };
    let tuple = Tree::Tuple("kept".to_owned(), None);
    assert_eq!(
        to_value(redactor.redact_view(&named)).unwrap(),
        json!({"Named": {"child": null}})
    );
    assert_eq!(
        to_value(redactor.redact_view(&tuple)).unwrap(),
        json!({"Tuple": ["kept", null]})
    );
}

/// Generic recursive Self paths preserve source generic arguments.
#[test]
fn test_generic_recursive_self_predicate_and_explicit_path_control() {
    #[derive(Debug, Redact)]
    struct Generic<'a, T, const N: usize> {
        #[serde(skip_serializing_if = "Self::is_none")]
        value: Option<T>,
        borrowed: &'a str,
        next: Option<Box<Generic<'a, T, N>>>,
        #[serde(skip_serializing)]
        bytes: [u8; N],
    }

    impl<'a, T, const N: usize> Generic<'a, T, N> {
        fn is_none(value: &Option<T>) -> bool {
            value.is_none()
        }
    }

    #[derive(Debug, Redact)]
    struct Node {
        #[serde(skip_serializing_if = "Node::empty")]
        value: String,
        next: Option<Box<Node>>,
    }

    impl Node {
        #[allow(clippy::ptr_arg)] // Serde skip predicates take the field's exact type.
        fn empty(value: &String) -> bool {
            value.is_empty()
        }
    }

    let redactor = Redactor::standard();
    let generic = Generic {
        value: None::<u32>,
        borrowed: "borrowed",
        next: Some(Box::new(Generic {
            value: Some(7u32),
            borrowed: "nested",
            next: None,
            bytes: [0; 2],
        })),
        bytes: [0; 2],
    };
    assert_eq!(
        to_value(redactor.redact_view(&generic)).unwrap(),
        json!({
            "borrowed": "borrowed",
            "next": {"value": 7, "borrowed": "nested", "next": null}
        })
    );
    let explicit = Node {
        value: String::new(),
        next: None,
    };
    assert_eq!(
        to_value(redactor.redact_view(&explicit)).unwrap(),
        json!({"next": null})
    );
}

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

/// A concrete predicate field does not make text-only formatting require
/// `Serialize` for the source field type.
#[test]
fn test_concrete_text_only_skip_predicate_supports_text_redaction() {
    #[derive(Debug)]
    struct TextOnly;

    #[derive(Debug, Redact)]
    struct Concrete {
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<TextOnly>,
    }

    let value = Concrete { value: Some(TextOnly) };
    let redactor = Redactor::standard();
    assert!(format!("{}", redactor.redact_view(&value)).contains("TextOnly"));
    assert!(redactor.redact_text(&value).complete_text().is_ok());
}

/// Saved predicates run once per real serialization and preserve JSON shape.
#[test]
fn test_concrete_skip_predicate_runs_only_when_serializing_projection() {
    static PREDICATE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn is_none(value: &Option<u32>) -> bool {
        PREDICATE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        value.is_none()
    }

    #[derive(Debug, Redact)]
    struct Concrete {
        #[serde(skip_serializing_if = "is_none")]
        value: Option<u32>,
    }

    let redactor = Redactor::standard();
    let some = Concrete { value: Some(7) };
    let view = redactor.redact_view(&some);
    assert_eq!(PREDICATE_CALLS.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(to_value(view).expect("Some projection"), json!({"value": 7}));
    assert_eq!(PREDICATE_CALLS.load(std::sync::atomic::Ordering::SeqCst), 1);

    let none = Concrete { value: None };
    let view = redactor.redact_view(&none);
    assert_eq!(PREDICATE_CALLS.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(to_value(view).expect("None projection"), json!({}));
    assert_eq!(PREDICATE_CALLS.load(std::sync::atomic::Ordering::SeqCst), 2);
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

/// Nested `Self` adapter type arguments keep the derived source identity.
#[test]
fn test_adapter_nested_self_uses_source_identity() {
    trait HasAssoc {
        type Assoc;
    }

    #[derive(Debug, Redact)]
    #[redact(serde)]
    struct Source<T> {
        #[serde(serialize_with = "Self::serialize_type_name::<&Self, _>")]
        reference: String,
        #[serde(serialize_with = "Self::serialize_type_name::<(Self,), _>")]
        tuple: String,
        #[serde(serialize_with = "Self::serialize_type_name::<Option<&Self>, _>")]
        nested_reference: String,
        #[serde(serialize_with = "Self::serialize_type_name::<<Self as HasAssoc>::Assoc, _>")]
        qualified_associated: String,
        #[serde(serialize_with = "Self::serialize_type_name::<Option<&String>, _>")]
        non_self: String,
        #[serde(skip)]
        marker: PhantomData<T>,
    }

    impl<T> HasAssoc for Source<T> {
        type Assoc = String;
    }

    impl<T> Source<T> {
        fn serialize_type_name<U, S: Serializer>(_: &String, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(std::any::type_name::<U>())
        }
    }

    let value = Source::<u32> {
        reference: String::new(),
        tuple: String::new(),
        nested_reference: String::new(),
        qualified_associated: String::new(),
        non_self: String::new(),
        marker: PhantomData,
    };
    let expected = json!({
        "reference": std::any::type_name::<&Source<u32>>(),
        "tuple": std::any::type_name::<(Source<u32>,)>(),
        "nested_reference": std::any::type_name::<Option<&Source<u32>>>(),
        "qualified_associated": std::any::type_name::<String>(),
        "non_self": std::any::type_name::<Option<&String>>(),
    });
    let redacted = to_value(Redactor::standard().redact_view(&value)).expect("adapter view serialization");
    let source = to_value(&value).expect("source serialization");

    assert_eq!(redacted, expected);
    assert_eq!(source, expected);
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

#[test]
fn test_source_self_bounds_keep_source_type_identity_in_projections() {
    trait Marker {}

    #[derive(Redact)]
    struct Record
    where
        Self: Marker,
    {
        value: u8,
    }

    impl Marker for Record {}

    #[derive(Redact)]
    #[redact(serde)]
    struct SourceRecord
    where
        Self: Marker,
    {
        value: u8,
    }

    impl Marker for SourceRecord {}

    let record = Record { value: 7 };
    assert_eq!(
        to_value(Redactor::standard().redact_view(&record)).expect("source Self view"),
        json!({"value": 7})
    );

    let source_record = SourceRecord { value: 9 };
    let view = to_value(Redactor::standard().redact_view(&source_record)).expect("source Serialize view");
    let source = to_value(&source_record).expect("ordinary derived source serialization");
    assert_eq!(view, json!({"value": 9}));
    assert_eq!(source, view);
}

#[test]
fn test_source_self_bounds_support_assoc_trait_and_const_paths() {
    trait HasAssoc {
        type Assoc;
        const SIZE: usize;
    }
    trait Uses<T> {}
    trait RefMarker {}
    impl<T> RefMarker for &T {}

    struct Plain<'a, T: Clone, const N: usize>
    where
        Self: Uses<Self>,
        <Self as HasAssoc>::Assoc: Clone,
        for<'b> &'b Self: RefMarker,
    {
        value: &'a T,
        bytes: [u8; N],
    }

    impl<'a, T: Clone, const N: usize> HasAssoc for Plain<'a, T, N> {
        type Assoc = u8;
        const SIZE: usize = N;
    }
    impl<'a, T: Clone, const N: usize> Uses<Plain<'a, T, N>> for Plain<'a, T, N> {}

    #[derive(Redact)]
    struct Constrained<'a, T: Clone, const N: usize>
    where
        Self: Uses<Self>,
        <Self as HasAssoc>::Assoc: Clone,
        for<'b> &'b Self: RefMarker,
    {
        value: &'a T,
        bytes: [u8; N],
    }

    impl<'a, T: Clone, const N: usize> HasAssoc for Constrained<'a, T, N> {
        type Assoc = u8;
        const SIZE: usize = N;
    }
    impl<'a, T: Clone, const N: usize> Uses<Constrained<'a, T, N>> for Constrained<'a, T, N> {}

    let text = String::from("value");
    let plain = Plain::<_, 2> {
        value: &text,
        bytes: [1, 2],
    };
    let constrained = Constrained::<_, 2> {
        value: &text,
        bytes: [3, 4],
    };
    let expected = json!({"value": "value", "bytes": [3, 4]});
    assert_eq!(
        to_value(Redactor::standard().redact_view(&constrained)).expect("Self-bound projection"),
        expected
    );
    assert_eq!(plain.value, constrained.value);
    assert_eq!(plain.bytes, [1, 2]);
    assert_eq!(<Plain<'_, String, 2> as HasAssoc>::SIZE, 2);
    assert_eq!(<Constrained<'_, String, 2> as HasAssoc>::SIZE, 2);
}
