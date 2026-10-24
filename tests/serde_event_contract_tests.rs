// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serde event contracts for redaction adapters.

#![cfg(all(feature = "derive", feature = "serde"))]

use std::cell::Cell;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::domain::internal::RedactSerializeScope;
use qubit_redact::domain::internal::RedactSerializeSource;
use qubit_redact::domain::internal::RedactedLevelSerializeRef;

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct NestedOption {
    #[redact(level = "secret")]
    value: Option<String>,
}

#[test]
fn test_level_option_preserves_some_and_none_events() {
    let policy = RedactionPolicy::standard();
    let value = Some(String::from("raw-secret"));
    let _scope = RedactSerializeScope::new(&policy);
    let adapter = RedactedLevelSerializeRef::new(&value, &policy, Sensitivity::Secret);
    serde_test::assert_ser_tokens(
        &adapter,
        &[serde_test::Token::Some, serde_test::Token::Str("<redacted>")],
    );

    let value: Option<String> = None;
    let adapter = RedactedLevelSerializeRef::new(&value, &policy, Sensitivity::Secret);
    serde_test::assert_ser_tokens(&adapter, &[serde_test::Token::None]);
}

#[test]
fn test_nested_option_projection_preserves_both_some_events() {
    let policy = RedactionPolicy::standard();
    let value = Some(NestedOption {
        value: Some(String::from("raw-secret")),
    });
    let projection = value.redacted_fields(&policy);
    let _scope = RedactSerializeScope::new(&policy);
    serde_test::assert_ser_tokens(
        &projection,
        &[
            serde_test::Token::Some,
            serde_test::Token::Struct {
                name: "NestedOption",
                len: 1,
            },
            serde_test::Token::Str("value"),
            serde_test::Token::Some,
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::StructEnd,
        ],
    );
}

#[test]
fn test_fixed_array_uses_tuple_and_vec_uses_sequence() {
    let policy = RedactionPolicy::standard();
    let array = [String::from("first"), String::from("second")];
    let _scope = RedactSerializeScope::new(&policy);
    let array_adapter = RedactedLevelSerializeRef::new(&array, &policy, Sensitivity::Secret);
    serde_test::assert_ser_tokens(
        &array_adapter,
        &[
            serde_test::Token::Tuple { len: 2 },
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::TupleEnd,
        ],
    );

    let values = vec![String::from("first"), String::from("second")];
    let values_adapter = RedactedLevelSerializeRef::new(&values, &policy, Sensitivity::Secret);
    serde_test::assert_ser_tokens(
        &values_adapter,
        &[
            serde_test::Token::Seq { len: Some(2) },
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::Str("<redacted>"),
            serde_test::Token::SeqEnd,
        ],
    );
}

#[test]
fn test_disabled_level_option_and_array_keep_some_and_tuple_events() {
    let policy = RedactionPolicy::disabled();
    let value = Some(String::from("visible"));
    let _scope = RedactSerializeScope::new(&policy);
    let adapter = RedactedLevelSerializeRef::new(&value, &policy, Sensitivity::Secret);
    serde_test::assert_ser_tokens(&adapter, &[serde_test::Token::Some, serde_test::Token::Str("visible")]);

    let array = [String::from("first"), String::from("second")];
    let adapter = RedactedLevelSerializeRef::new(&array, &policy, Sensitivity::Secret);
    serde_test::assert_ser_tokens(
        &adapter,
        &[
            serde_test::Token::Tuple { len: 2 },
            serde_test::Token::Str("first"),
            serde_test::Token::Str("second"),
            serde_test::Token::TupleEnd,
        ],
    );
}

#[cfg(feature = "json")]
#[test]
fn test_json_option_preserves_some_event() {
    use qubit_redact::domain::internal::RedactedJsonSerializeRef;

    let policy = RedactionPolicy::standard();
    let value = Some(String::from("not-json"));
    let _scope = RedactSerializeScope::new(&policy);
    let adapter = RedactedJsonSerializeRef::new(&value, &policy);
    serde_test::assert_ser_tokens(
        &adapter,
        &[serde_test::Token::Some, serde_test::Token::Str("<redacted>")],
    );
}

struct ReadabilityProbe {
    calls: Cell<usize>,
}

impl serde::Serialize for ReadabilityProbe {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        self.calls.set(self.calls.get() + 1);
        let branch = if serializer.is_human_readable() {
            "readable"
        } else {
            "compact"
        };
        let mut output = serializer.serialize_struct("ReadabilityProbe", 1)?;
        output.serialize_field("branch", branch)?;
        output.end()
    }
}

#[derive(Clone, Copy)]
struct TaggedProbe<'a>(&'a ReadabilityProbe);

impl serde::Serialize for TaggedProbe<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        qubit_redact::domain::internal::serialize_internally_tagged(
            serializer, "Probe", "Variant", "kind", "variant", self.0,
        )
    }
}

#[test]
fn test_internally_tagged_serializer_forwards_human_readability() {
    use serde_test::Configure;

    let policy = RedactionPolicy::standard();
    let _scope = RedactSerializeScope::new(&policy);
    let probe = ReadabilityProbe { calls: Cell::new(0) };
    let tagged = TaggedProbe(&probe);
    serde_test::assert_ser_tokens(
        &tagged.readable(),
        &[
            serde_test::Token::Map { len: Some(2) },
            serde_test::Token::Str("kind"),
            serde_test::Token::Str("variant"),
            serde_test::Token::Str("branch"),
            serde_test::Token::Str("readable"),
            serde_test::Token::MapEnd,
        ],
    );
    assert_eq!(probe.calls.get(), 1, "source Serialize must run once");

    serde_test::assert_ser_tokens(
        &tagged.compact(),
        &[
            serde_test::Token::Map { len: Some(2) },
            serde_test::Token::Str("kind"),
            serde_test::Token::Str("variant"),
            serde_test::Token::Str("branch"),
            serde_test::Token::Str("compact"),
            serde_test::Token::MapEnd,
        ],
    );
    assert_eq!(probe.calls.get(), 2, "each adapter serialization must run once");
}
