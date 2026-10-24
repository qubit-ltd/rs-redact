// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Borrowed projection capability regressions for derived sources.

#![cfg(all(feature = "derive", feature = "serde", feature = "json"))]

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Redact)]
#[redact(crate = qubit_redact)]
struct Child<'a> {
    #[redact(level = "secret")]
    password: &'a str,
}

#[derive(Redact)]
#[redact(crate = qubit_redact)]
struct Parent<T> {
    #[redact(nested)]
    child: T,
}

#[derive(Redact, serde::Serialize)]
#[redact(crate = qubit_redact)]
struct SourceSerializeChild {
    #[redact(level = "secret")]
    password: String,
}

#[test]
fn test_local_borrowed_child_projects_through_direct_vec_option_and_nested_paths() {
    let local = String::from("raw-password");
    let child = Child { password: &local };
    let redactor = Redactor::standard();

    let direct = serde_json::to_value(redactor.redact_view(&child)).expect("direct view");
    assert_eq!(direct["password"], "<redacted>");
    assert!(
        !redactor
            .to_json(&child)
            .expect("direct JSON")
            .contains("raw-password")
    );

    let values = vec![Child { password: &local }];
    let encoded = serde_json::to_value(redactor.redact_view(&values)).expect("vector view");
    assert_eq!(encoded[0]["password"], "<redacted>");
    assert!(
        !redactor
            .to_json(&values)
            .expect("vector JSON")
            .contains("raw-password")
    );

    let some = Some(Child { password: &local });
    let encoded = serde_json::to_value(redactor.redact_view(&some)).expect("some view");
    assert_eq!(encoded["password"], "<redacted>");
    assert!(
        !redactor
            .to_json(&some)
            .expect("some JSON")
            .contains("raw-password")
    );

    let none: Option<Child<'_>> = None;
    assert!(
        serde_json::to_value(redactor.redact_view(&none))
            .expect("none view")
            .is_null()
    );
    assert_eq!(redactor.to_json(&none).expect("none JSON"), "null");

    let borrowed = Child { password: &local };
    let optional_reference = Some(&borrowed);
    assert!(
        !redactor
            .to_json(&optional_reference)
            .expect("optional reference JSON")
            .contains("raw-password")
    );

    let boxed = vec![Box::new(Child { password: &local })];
    assert!(
        !redactor
            .to_json(&boxed)
            .expect("boxed child vector JSON")
            .contains("raw-password")
    );

    let arrays = vec![[Child { password: &local }, Child { password: &local }]];
    assert!(
        !redactor
            .to_json(&arrays)
            .expect("array vector JSON")
            .contains("raw-password")
    );

    let tuple = (Child { password: &local }, Child { password: &local });
    assert!(
        !redactor
            .to_json(&tuple)
            .expect("tuple JSON")
            .contains("raw-password")
    );

    let parent = Parent {
        child: Child { password: &local },
    };
    let encoded = serde_json::to_value(redactor.redact_view(&parent)).expect("parent view");
    assert_eq!(encoded["child"]["password"], "<redacted>");
    assert!(
        !redactor
            .to_json(&parent)
            .expect("parent JSON")
            .contains("raw-password")
    );
}

#[test]
fn test_ordinary_source_serialize_remains_unredacted_and_opt_in_view_is_redacted() {
    let source = SourceSerializeChild {
        password: "raw-password".into(),
    };
    let encoded = serde_json::to_value(&source).expect("ordinary source Serialize");
    assert_eq!(encoded["password"], "raw-password");

    let view =
        serde_json::to_value(Redactor::standard().redact_view(&source)).expect("redacted view");
    assert_eq!(view["password"], "<redacted>");
}

#[test]
fn test_array_and_tuple_projection_keep_their_serde_event_shapes() {
    let local = String::from("raw-password");
    let redactor = Redactor::standard();
    let array = [Child { password: &local }, Child { password: &local }];
    serde_test::assert_ser_tokens(
        &redactor.redact_view(&array),
        &[
            serde_test::Token::Seq { len: Some(2) },
            serde_test::Token::Struct {
                name: "Child",
                len: 1,
            },
            serde_test::Token::Str("password"),
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::StructEnd,
            serde_test::Token::Struct {
                name: "Child",
                len: 1,
            },
            serde_test::Token::Str("password"),
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::StructEnd,
            serde_test::Token::SeqEnd,
        ],
    );

    let tuple = (Child { password: &local }, Child { password: &local });
    serde_test::assert_ser_tokens(
        &redactor.redact_view(&tuple),
        &[
            serde_test::Token::Tuple { len: 2 },
            serde_test::Token::Struct {
                name: "Child",
                len: 1,
            },
            serde_test::Token::Str("password"),
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::StructEnd,
            serde_test::Token::Struct {
                name: "Child",
                len: 1,
            },
            serde_test::Token::Str("password"),
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::StructEnd,
            serde_test::Token::TupleEnd,
        ],
    );
}
