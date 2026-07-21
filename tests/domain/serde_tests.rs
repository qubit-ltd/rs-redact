// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for optional serialization of redacted domain views.

use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    io::{
        self,
        Write,
    },
};

use qubit_redact::{
    Redact,
    RedactedMap,
    RedactionPolicy,
    Sensitivity,
};
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
    RedactionPolicy::empty_builder()
        .raise("api_key", Sensitivity::Secret)
        .build()
        .expect("the field rule is valid")
}

/// Builds an account containing distinct raw sentinels.
fn account() -> ApiAccount {
    ApiAccount {
        account_id: 9,
        password: Some("raw-password".to_owned()),
        metadata: BTreeMap::from([(
            "api_key".to_owned(),
            "raw-api-key".to_owned(),
        )]),
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
            let raw = serde_json::to_value(&value)
                .expect("raw rename_all serialization should succeed");
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
    let raw =
        serde_json::to_string(&value).expect("raw serialization succeeds");

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
    let error = serde_json::to_writer(
        FailingWriter,
        &account().redacted_with(&policy()),
    )
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
    let metadata =
        BTreeMap::from([("api_key".to_owned(), "raw-api-key".to_owned())]);
    let redacted = RedactedMap::new(&metadata, policy());

    let open_error = serde_json::to_writer(FailingWriter, &redacted)
        .expect_err("the writer rejects the opening map delimiter");
    let entry_error =
        serde_json::to_writer(FailAfter { remaining: 1 }, &redacted)
            .expect_err("the writer rejects the first map entry");

    assert!(open_error.is_io());
    assert!(entry_error.is_io());
}
