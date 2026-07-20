// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for optional serialization of redacted domain views.

use std::{
    collections::BTreeMap,
    io::{
        self,
        Write,
    },
};

use qubit_redact::{
    Redact,
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
