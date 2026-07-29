// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for optional serialization of redacted domain views.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

use qubit_redact::{Redact, RedactedMap, RedactionPolicy, Sensitivity};
use qubit_redact_derive::Redact;
use serde::Serialize;

/// Nested serializable profile.
#[derive(Redact, Serialize)]
#[redact(serde)]
struct Profile {
    /// Explicit wire name.
    #[serde(rename = "wire_name")]
    name: String,
    /// Secret nested value.
    #[redact(level = "secret")]
    token: String,
}

/// Serializable account covering supported serde field controls.
#[derive(Redact, Serialize)]
#[redact(serde)]
#[serde(rename_all = "camelCase")]
struct ApiAccount {
    /// Plain identifier renamed by the container rule.
    account_id: u64,
    /// Optional explicitly sensitive value.
    #[redact(level = "secret")]
    password: Option<String>,
    /// Runtime-keyed sensitive values.
    #[redact(map)]
    metadata: BTreeMap<String, String>,
    /// Field omitted from every redacted representation.
    #[redact(skip)]
    internal_note: String,
    /// Field conditionally omitted according to its raw value.
    #[serde(skip_serializing_if = "Option::is_none")]
    nickname: Option<String>,
    /// Nested redacted object.
    #[redact(nested)]
    profile: Profile,
    /// Optional boxed nested object.
    #[redact(nested)]
    backup: Option<Box<Profile>>,
    /// Nested sequence.
    #[redact(nested)]
    history: Vec<Profile>,
    /// Field omitted by serde semantics.
    #[serde(skip)]
    serde_internal: String,
    /// Field omitted specifically during serialization.
    #[serde(skip_serializing)]
    write_only: String,
}

/// Serializable newtype preserving its scalar wire shape.
#[derive(Redact, Serialize)]
#[redact(serde)]
struct SecretNewtype(#[redact(level = "secret")] String);

/// Serializable tuple struct preserving positional omission.
#[derive(Redact, Serialize)]
#[redact(serde)]
struct SecretTuple(
    #[redact(level = "secret")] String,
    &'static str,
    #[redact(skip)] String,
);

/// Serializable unit struct preserving its unit wire shape.
#[derive(Redact, Serialize)]
#[redact(serde)]
struct SerdeMarker;

/// Externally tagged enum covering names, fields, tuples, units, and skips.
#[derive(Redact, Serialize)]
#[redact(serde)]
#[serde(rename_all = "snake_case", rename_all_fields = "camelCase")]
enum ExternalMessage {
    /// Named content uses the container field rule.
    Record {
        /// Plain field renamed by `rename_all_fields`.
        account_id: u64,
        /// Secret field.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple content uses an explicit variant name.
    #[serde(rename = "wire_tuple")]
    Tuple(#[redact(level = "secret")] String, &'static str),
    /// Unit content uses the container variant rule.
    UnitValue,
    /// Variant field rule overrides the container field rule.
    #[serde(rename_all = "UPPERCASE")]
    Override {
        /// Field renamed by the variant rule.
        some_field: &'static str,
    },
    /// Skipped variants must return a serializer error when selected.
    #[serde(skip_serializing)]
    Hidden {
        /// Raw value that must never reach the serializer.
        raw_secret: String,
    },
}

/// Internally tagged enum covering the structurally valid variant shapes.
#[derive(Redact, Serialize)]
#[redact(serde)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum InternalMessage {
    /// Named variant merges redacted fields beside the tag.
    Record {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Unit variant contains only the tag.
    Ready,
    /// Newtype content may merge a redacted struct into the tagged object.
    Profile(#[redact(nested)] Profile),
    /// Conditionally omitted newtype content leaves only the tag.
    Optional(
        #[redact(nested)]
        #[serde(skip_serializing_if = "Option::is_none")]
        Option<Profile>,
    ),
}

/// Adjacently tagged enum covering named, tuple, and unit content.
#[derive(Redact, Serialize)]
#[redact(serde)]
#[serde(tag = "kind", content = "payload")]
enum AdjacentMessage {
    /// Named content.
    Record {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple content.
    Tuple(#[redact(level = "secret")] String, &'static str),
    /// Unit variant has no content entry.
    Ready,
}

/// Untagged enum covering named, tuple, and unit content.
#[derive(Redact, Serialize)]
#[redact(serde)]
#[serde(untagged)]
enum UntaggedMessage {
    /// Named object content.
    Record {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple array content.
    Tuple(#[redact(level = "secret")] String, &'static str),
    /// Unit content serializes as null.
    Ready,
}

/// Newtype whose only field is omitted from the redacted wire shape.
#[allow(dead_code)]
#[derive(Redact)]
#[redact(serde)]
struct EmptyNewtype(#[redact(skip)] String);

/// Externally tagged variants with empty or forbidden payloads.
#[allow(dead_code)]
#[derive(Redact)]
#[redact(serde)]
enum ExternalEmptyMessage {
    /// Omitted newtype content becomes a unit variant.
    EmptyNewtype(#[redact(skip)] String),
    /// Omitted named content remains an empty object.
    EmptyNamed {
        /// Payload omitted from the redacted representation.
        #[redact(skip)]
        hidden: String,
    },
    /// Omitted tuple content remains an empty array.
    EmptyTuple(#[redact(skip)] String, #[serde(skip)] String),
    /// Skipped tuple variants reject serialization.
    #[serde(skip)]
    HiddenTuple(String),
    /// Skipped unit variants reject serialization.
    #[serde(skip)]
    HiddenUnit,
}

/// Internally tagged newtype with no serializable payload.
#[allow(dead_code)]
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum InternalEmptyMessage {
    /// Omitted content leaves only the internal tag.
    Empty(#[redact(skip)] String),
}

/// Adjacently tagged variants with empty content shapes.
#[allow(dead_code)]
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "payload")]
enum AdjacentEmptyMessage {
    /// Omitted named content remains an empty object.
    Named {
        /// Payload omitted from the redacted representation.
        #[redact(skip)]
        hidden: String,
    },
    /// Omitted tuple content remains an empty array.
    Tuple(#[redact(skip)] String, #[serde(skip)] String),
    /// Omitted newtype content removes the content member.
    Newtype(#[redact(skip)] String),
}

/// Untagged newtypes with absent and present redacted content.
#[allow(dead_code)]
#[derive(Redact)]
#[redact(serde)]
#[serde(untagged)]
enum UntaggedNewtypeMessage {
    /// Omitted content serializes as a unit.
    Empty(#[redact(skip)] String),
    /// Plain content serializes directly.
    Value(String),
}

/// Writer that always returns an I/O error.
struct FailingWriter;

impl Write for FailingWriter {
    /// Rejects every write operation.
    #[inline(always)]
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("intentional serializer failure"))
    }

    /// Rejects every flush operation.
    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("intentional serializer failure"))
    }
}

/// Writer that accepts a fixed prefix before returning an I/O error.
struct FailAfter {
    /// Number of bytes still accepted.
    remaining: usize,
}

impl Write for FailAfter {
    /// Accepts at most the configured byte budget.
    #[inline]
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("intentional serializer failure"));
        }
        let accepted = self.remaining.min(buffer.len());
        self.remaining -= accepted;
        Ok(accepted)
    }

    /// Flushes successfully because only data writes are under test.
    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Builds the deterministic policy used by serialization tests.
fn policy() -> RedactionPolicy {
    RedactionPolicy::builder()
        .raise("api_key", Sensitivity::Secret)
        .build()
        .expect("the field rule is valid")
}

/// Builds an account containing distinct raw sentinels.
fn account() -> ApiAccount {
    ApiAccount {
        account_id: 9,
        password: Some("raw-password".to_owned()),
        metadata: BTreeMap::from([("api_key".to_owned(), "raw-api-key".to_owned())]),
        internal_note: "raw-internal".to_owned(),
        nickname: None,
        profile: Profile {
            name: "Alice".to_owned(),
            token: "raw-nested-token".to_owned(),
        },
        backup: Some(Box::new(Profile {
            name: "Bob".to_owned(),
            token: "raw-backup-token".to_owned(),
        })),
        history: vec![Profile {
            name: "Carol".to_owned(),
            token: "raw-history-token".to_owned(),
        }],
        serde_internal: "raw-serde-internal".to_owned(),
        write_only: "raw-write-only".to_owned(),
    }
}

/// Returns the owned object-key set produced by a JSON value.
///
/// # Parameters
///
/// * `value` - Serialized value expected to contain a JSON object.
///
/// # Returns
///
/// The object's keys in deterministic order.
///
/// # Panics
///
/// Panics when `value` is not a JSON object.
fn object_keys(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("rename_all test values should serialize as objects")
        .keys()
        .cloned()
        .collect()
}

/// Verifies every supported `rename_all` rule emits the same keys as Serde.
#[test]
fn test_redacted_serde_rename_all_matches_serde() {
    macro_rules! assert_rule {
        ($rule:literal) => {{
            #[allow(non_snake_case)]
            #[derive(Redact, Serialize)]
            #[redact(serde)]
            #[serde(rename_all = $rule)]
            struct RenameFields {
                /// Mixed-case field that distinguishes lowercase semantics.
                #[redact(level = "secret")]
                HTTP_status: String,
                /// Ordinary snake-case field that distinguishes separators.
                some_value: String,
            }

            let value = RenameFields {
                HTTP_status: "raw-status".to_owned(),
                some_value: "plain-value".to_owned(),
            };
            let raw =
                serde_json::to_value(&value).expect("raw rename_all serialization should succeed");
            let redacted = serde_json::to_value(value.redacted_with(&policy()))
                .expect("redacted rename_all serialization should succeed");

            assert_eq!(
                object_keys(&redacted),
                object_keys(&raw),
                "redacted keys should match serde for {}",
                $rule,
            );
        }};
    }

    assert_rule!("lowercase");
    assert_rule!("UPPERCASE");
    assert_rule!("PascalCase");
    assert_rule!("camelCase");
    assert_rule!("snake_case");
    assert_rule!("SCREAMING_SNAKE_CASE");
    assert_rule!("kebab-case");
    assert_rule!("SCREAMING-KEBAB-CASE");
}

/// Verifies redacted serialization preserves shape and excludes raw secrets.
#[test]
fn test_redacted_serde_preserves_shape_and_never_serializes_raw_values() {
    let value = account();

    let json = serde_json::to_string(&value.redacted_with(&policy()))
        .expect("redacted serialization succeeds");
    let raw = serde_json::to_string(&value).expect("raw serialization succeeds");

    assert!(json.contains(r#""accountId":9"#));
    assert!(json.contains(r#""wire_name":"Alice""#));
    assert!(!json.contains("raw-password"));
    assert!(!json.contains("raw-api-key"));
    assert!(!json.contains("raw-nested-token"));
    assert!(!json.contains("raw-backup-token"));
    assert!(!json.contains("raw-history-token"));
    assert!(!json.contains("internalNote"));
    assert!(!json.contains("nickname"));
    assert!(!json.contains("serdeInternal"));
    assert!(!json.contains("writeOnly"));
    assert!(raw.contains("raw-password"));
    assert!(raw.contains("raw-api-key"));
    assert!(raw.contains("raw-nested-token"));
    assert!(raw.contains("raw-backup-token"));
    assert!(raw.contains("raw-history-token"));
}

/// Verifies optional `None` retains its serialized shape when not skipped.
#[test]
fn test_redacted_serde_serializes_explicit_none_as_null() {
    let mut value = account();
    value.password = None;

    let json = serde_json::to_string(&value.redacted_with(&policy()))
        .expect("redacted serialization succeeds");

    assert!(json.contains(r#""password":null"#));
}

/// Verifies downstream serializer errors propagate unchanged.
#[test]
fn test_redacted_serde_propagates_serializer_errors() {
    let error = serde_json::to_writer(FailingWriter, &account().redacted_with(&policy()))
        .expect_err("the writer rejects serialization");

    assert!(error.is_io());
}

/// Verifies empty runtime-keyed maps serialize as empty objects.
#[test]
fn test_redacted_serde_serializes_empty_map() {
    let mut value = account();
    value.metadata.clear();

    let json = serde_json::to_value(value.redacted_with(&policy()))
        .expect("redacted serialization succeeds");

    assert_eq!(json["metadata"], serde_json::json!({}));
}

/// Verifies absent and empty nested containers preserve their wire shape.
#[test]
fn test_redacted_serde_preserves_absent_and_empty_nested_containers() {
    let mut value = account();
    value.backup = None;
    value.history.clear();

    let json = serde_json::to_value(value.redacted_with(&policy()))
        .expect("redacted serialization succeeds");

    assert_eq!(json["backup"], serde_json::Value::Null);
    assert_eq!(json["history"], serde_json::json!([]));
}

/// Verifies map serializer errors propagate while opening and writing entries.
#[test]
fn test_redacted_map_serde_propagates_serializer_errors() {
    let metadata = BTreeMap::from([("api_key".to_owned(), "raw-api-key".to_owned())]);
    let redacted = RedactedMap::new(&metadata, policy());

    let open_error = serde_json::to_writer(FailingWriter, &redacted)
        .expect_err("the writer rejects the opening map delimiter");
    let entry_error = serde_json::to_writer(FailAfter { remaining: 1 }, &redacted)
        .expect_err("the writer rejects the first map entry");

    assert!(open_error.is_io());
    assert!(entry_error.is_io());

    let visible = BTreeMap::from([("label".to_owned(), "visible".to_owned())]);
    let visible_error = serde_json::to_writer(
        FailAfter { remaining: 1 },
        &RedactedMap::new(&visible, policy()),
    )
    .expect_err("the writer rejects a visible map entry");

    assert!(visible_error.is_io());

    let mixed = BTreeMap::from([
        ("api_key".to_owned(), "raw-api-key".to_owned()),
        ("label".to_owned(), "visible".to_owned()),
    ]);
    let mixed = RedactedMap::new(&mixed, policy());
    let output_len = serde_json::to_vec(&mixed)
        .expect("the complete redacted map should serialize")
        .len();

    for remaining in 0..output_len {
        let error = serde_json::to_writer(FailAfter { remaining }, &mixed)
            .expect_err("each truncated destination should reject the map");
        assert!(error.is_io());
    }
}

/// Verifies newtype, tuple, and unit structs retain their Serde wire shapes.
#[test]
fn test_redacted_serde_supports_unnamed_and_unit_structs() {
    let newtype = SecretNewtype(String::from("raw-newtype"));
    let tuple = SecretTuple(
        String::from("raw-tuple"),
        "shown",
        String::from("raw-skipped"),
    );

    let newtype_json =
        serde_json::to_value(newtype.redacted()).expect("redacted newtype serialization succeeds");
    let tuple_json =
        serde_json::to_value(tuple.redacted()).expect("redacted tuple serialization succeeds");
    let unit_json =
        serde_json::to_value(SerdeMarker.redacted()).expect("redacted unit serialization succeeds");

    assert_eq!(newtype_json, serde_json::json!("<redacted>"));
    assert_eq!(tuple_json, serde_json::json!(["<redacted>", "shown"]));
    assert_eq!(unit_json, serde_json::Value::Null);
}

/// Verifies externally tagged enums preserve variant and field renaming while
/// redacting every selected payload.
#[test]
fn test_redacted_serde_supports_externally_tagged_enums() {
    let record = ExternalMessage::Record {
        account_id: 7,
        secret: String::from("raw-record"),
    };
    let tuple = ExternalMessage::Tuple(String::from("raw-tuple"), "shown");
    let override_fields = ExternalMessage::Override {
        some_field: "shown",
    };

    let record_json = serde_json::to_value(record.redacted())
        .expect("redacted named variant serialization succeeds");
    let tuple_json = serde_json::to_value(tuple.redacted())
        .expect("redacted tuple variant serialization succeeds");
    let unit_json = serde_json::to_value(ExternalMessage::UnitValue.redacted())
        .expect("redacted unit variant serialization succeeds");
    let override_json = serde_json::to_value(override_fields.redacted())
        .expect("redacted renamed fields serialize successfully");

    assert_eq!(
        record_json,
        serde_json::json!({
            "record": {"accountId": 7, "secret": "<redacted>"}
        }),
    );
    assert_eq!(
        tuple_json,
        serde_json::json!({"wire_tuple": ["<redacted>", "shown"]}),
    );
    assert_eq!(unit_json, serde_json::json!("unit_value"));
    assert_eq!(
        override_json,
        serde_json::json!({"override": {"SOME_FIELD": "shown"}}),
    );
}

/// Verifies internally tagged enums merge their tag and redacted fields.
#[test]
fn test_redacted_serde_supports_internally_tagged_enums() {
    let record = InternalMessage::Record {
        secret: String::from("raw-internal"),
    };

    let record_json = serde_json::to_value(record.redacted())
        .expect("redacted internally tagged variant serialization succeeds");
    let unit_json = serde_json::to_value(InternalMessage::Ready.redacted())
        .expect("redacted internally tagged unit serialization succeeds");
    let profile = InternalMessage::Profile(Profile {
        name: String::from("Alice"),
        token: String::from("raw-profile-token"),
    });
    let profile_json = serde_json::to_value(profile.redacted())
        .expect("redacted internally tagged newtype serialization succeeds");
    let optional_json = serde_json::to_value(InternalMessage::Optional(None).redacted())
        .expect("omitted internally tagged newtype serialization succeeds");

    assert_eq!(
        record_json,
        serde_json::json!({"kind": "record", "secret": "<redacted>"}),
    );
    assert_eq!(unit_json, serde_json::json!({"kind": "ready"}));
    assert_eq!(
        profile_json,
        serde_json::json!({
            "kind": "profile",
            "wire_name": "Alice",
            "token": "<redacted>"
        }),
    );
    assert_eq!(optional_json, serde_json::json!({"kind": "optional"}));
}

/// Verifies adjacently tagged enums wrap redacted content under the configured
/// tag and content keys.
#[test]
fn test_redacted_serde_supports_adjacently_tagged_enums() {
    let record = AdjacentMessage::Record {
        secret: String::from("raw-adjacent"),
    };
    let tuple = AdjacentMessage::Tuple(String::from("raw-tuple"), "shown");

    let record_json = serde_json::to_value(record.redacted())
        .expect("redacted adjacent named serialization succeeds");
    let tuple_json = serde_json::to_value(tuple.redacted())
        .expect("redacted adjacent tuple serialization succeeds");
    let unit_json = serde_json::to_value(AdjacentMessage::Ready.redacted())
        .expect("redacted adjacent unit serialization succeeds");

    assert_eq!(
        record_json,
        serde_json::json!({
            "kind": "Record",
            "payload": {"secret": "<redacted>"}
        }),
    );
    assert_eq!(
        tuple_json,
        serde_json::json!({
            "kind": "Tuple",
            "payload": ["<redacted>", "shown"]
        }),
    );
    assert_eq!(unit_json, serde_json::json!({"kind": "Ready"}));
}

/// Verifies untagged enums serialize only their redacted content shape.
#[test]
fn test_redacted_serde_supports_untagged_enums() {
    let record = UntaggedMessage::Record {
        secret: String::from("raw-untagged"),
    };
    let tuple = UntaggedMessage::Tuple(String::from("raw-tuple"), "shown");

    let record_json = serde_json::to_value(record.redacted())
        .expect("redacted untagged named serialization succeeds");
    let tuple_json = serde_json::to_value(tuple.redacted())
        .expect("redacted untagged tuple serialization succeeds");
    let unit_json = serde_json::to_value(UntaggedMessage::Ready.redacted())
        .expect("redacted untagged unit serialization succeeds");

    assert_eq!(record_json, serde_json::json!({"secret": "<redacted>"}),);
    assert_eq!(tuple_json, serde_json::json!(["<redacted>", "shown"]));
    assert_eq!(unit_json, serde_json::Value::Null);
}

/// Verifies omitted fields preserve each container's empty wire shape.
#[test]
fn test_redacted_serde_preserves_empty_container_shapes() {
    let newtype = EmptyNewtype("raw-newtype".to_owned());
    let external_newtype = ExternalEmptyMessage::EmptyNewtype("raw-external".to_owned());
    let external_named = ExternalEmptyMessage::EmptyNamed {
        hidden: "raw-named".to_owned(),
    };
    let external_tuple =
        ExternalEmptyMessage::EmptyTuple("raw-first".to_owned(), "raw-second".to_owned());
    let internal = InternalEmptyMessage::Empty("raw-internal".to_owned());
    let adjacent_named = AdjacentEmptyMessage::Named {
        hidden: "raw-adjacent-named".to_owned(),
    };
    let adjacent_tuple = AdjacentEmptyMessage::Tuple(
        "raw-adjacent-first".to_owned(),
        "raw-adjacent-second".to_owned(),
    );
    let adjacent_newtype = AdjacentEmptyMessage::Newtype("raw-adjacent".to_owned());
    let untagged_empty = UntaggedNewtypeMessage::Empty("raw-untagged".to_owned());
    let untagged_value = UntaggedNewtypeMessage::Value("visible".to_owned());

    assert_eq!(
        serde_json::to_value(newtype.redacted()).expect("empty newtype serialization succeeds"),
        serde_json::Value::Null,
    );
    assert_eq!(
        serde_json::to_value(external_newtype.redacted())
            .expect("empty external newtype serialization succeeds"),
        serde_json::json!("EmptyNewtype"),
    );
    assert_eq!(
        serde_json::to_value(external_named.redacted())
            .expect("empty external named serialization succeeds"),
        serde_json::json!({"EmptyNamed": {}}),
    );
    assert_eq!(
        serde_json::to_value(external_tuple.redacted())
            .expect("empty external tuple serialization succeeds"),
        serde_json::json!({"EmptyTuple": []}),
    );
    assert_eq!(
        serde_json::to_value(internal.redacted())
            .expect("empty internal newtype serialization succeeds"),
        serde_json::json!({"kind": "Empty"}),
    );
    assert_eq!(
        serde_json::to_value(adjacent_named.redacted())
            .expect("empty adjacent named serialization succeeds"),
        serde_json::json!({"kind": "Named", "payload": {}}),
    );
    assert_eq!(
        serde_json::to_value(adjacent_tuple.redacted())
            .expect("empty adjacent tuple serialization succeeds"),
        serde_json::json!({"kind": "Tuple", "payload": []}),
    );
    assert_eq!(
        serde_json::to_value(adjacent_newtype.redacted())
            .expect("empty adjacent newtype serialization succeeds"),
        serde_json::json!({"kind": "Newtype"}),
    );
    assert_eq!(
        serde_json::to_value(untagged_empty.redacted())
            .expect("empty untagged newtype serialization succeeds"),
        serde_json::Value::Null,
    );
    assert_eq!(
        serde_json::to_value(untagged_value.redacted())
            .expect("plain untagged newtype serialization succeeds"),
        serde_json::json!("visible"),
    );
}

/// Verifies a selected skipped variant returns an error without exposing its
/// payload.
#[test]
fn test_redacted_serde_rejects_selected_skipped_variant() {
    let hidden = ExternalMessage::Hidden {
        raw_secret: String::from("raw-hidden"),
    };

    let error = serde_json::to_string(&hidden.redacted())
        .expect_err("selected skipped variants must fail serialization");

    assert!(!error.to_string().contains("raw-hidden"));
}

/// Verifies skipped tuple and unit variants use the same rejection policy.
#[test]
fn test_redacted_serde_rejects_skipped_tuple_and_unit_variants() {
    let hidden_tuple = ExternalEmptyMessage::HiddenTuple("raw-hidden".to_owned());
    let tuple_error = serde_json::to_string(&hidden_tuple.redacted())
        .expect_err("selected skipped tuple variants must fail");
    let unit_error = serde_json::to_string(&ExternalEmptyMessage::HiddenUnit.redacted())
        .expect_err("selected skipped unit variants must fail");

    assert!(!tuple_error.to_string().contains("raw-hidden"));
    assert_eq!(
        tuple_error.to_string(),
        "cannot serialize skipped redacted variant `HiddenTuple`",
    );
    assert_eq!(
        unit_error.to_string(),
        "cannot serialize skipped redacted variant `HiddenUnit`",
    );
}
