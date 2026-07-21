// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for explicit destructive domain-object redaction.

use std::{
    borrow::Cow,
    collections::HashMap,
};

use qubit_redact::{
    MaskPolicy,
    RedactMut,
    RedactValueMut,
    RedactionPolicy,
    Sensitivity,
};
use qubit_redact_derive::RedactMut;

/// Mutable leaf used by nested redaction.
#[derive(Clone, RedactMut)]
struct MutableCredential {
    /// Secret token.
    #[redact(level = "secret")]
    token: String,
}

/// Mutable account covering every field mode.
#[derive(Clone, RedactMut)]
struct MutableAccount {
    /// Plain data left unchanged.
    id: u64,
    /// Explicitly sensitive owned value.
    #[redact(level = "secret")]
    password: String,
    /// Values classified by runtime key.
    #[redact(map)]
    metadata: HashMap<String, String>,
    /// Skipped data left unchanged by destructive redaction.
    #[redact(skip)]
    internal_note: String,
    /// Direct nested object.
    #[redact(nested)]
    primary: MutableCredential,
    /// Optional boxed nested object.
    #[redact(nested)]
    backup: Option<Box<MutableCredential>>,
    /// Nested sequence.
    #[redact(nested)]
    history: Vec<MutableCredential>,
}

/// Builds a mutable account containing distinct raw sentinels.
fn account() -> MutableAccount {
    MutableAccount {
        id: 3,
        password: "raw-password".to_owned(),
        metadata: HashMap::from([(
            "token".to_owned(),
            "raw-map-token".to_owned(),
        )]),
        internal_note: "unchanged".to_owned(),
        primary: MutableCredential {
            token: "raw-primary".to_owned(),
        },
        backup: Some(Box::new(MutableCredential {
            token: "raw-backup".to_owned(),
        })),
        history: vec![MutableCredential {
            token: "raw-history".to_owned(),
        }],
    }
}

/// Builds an explicit policy with an easily identified secret mask.
fn strict_policy() -> RedactionPolicy {
    RedactionPolicy::empty_builder()
        .raise("token", Sensitivity::Secret)
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[strict]"))
        .build()
        .expect("the fixed replacement and field rule are valid")
}

/// Verifies clone-based conversion changes only the returned copy.
#[test]
fn test_to_redacted_with_changes_only_the_clone() {
    let original = account();

    let copy = original.to_redacted_with(&strict_policy());

    assert_eq!(original.password, "raw-password");
    assert_eq!(original.metadata["token"], "raw-map-token");
    assert_eq!(copy.password, "[strict]");
    assert_eq!(copy.metadata["token"], "[strict]");
    assert_eq!(copy.primary.token, "[strict]");
    assert_eq!(copy.backup.as_ref().expect("present").token, "[strict]");
    assert_eq!(copy.history[0].token, "[strict]");
    assert_eq!(copy.id, 3);
    assert_eq!(copy.internal_note, "unchanged");
}

/// Verifies the explicit in-place and consuming operations.
#[test]
fn test_explicit_in_place_and_consuming_operations() {
    let policy = strict_policy();
    let mut in_place = account();
    in_place.redact_in_place_with(&policy);
    let consumed = account().into_redacted_with(&policy);

    assert_eq!(in_place.password, "[strict]");
    assert_eq!(consumed.password, "[strict]");
    assert_eq!(consumed.metadata["token"], "[strict]");
}

/// Verifies all parameterless operations use a default policy snapshot.
#[test]
fn test_default_in_place_consuming_and_clone_operations() {
    let mut in_place = account();
    in_place.redact_in_place();
    let consumed = account().into_redacted();
    let cloned = account().to_redacted();

    assert_ne!(in_place.password, "raw-password");
    assert_ne!(consumed.password, "raw-password");
    assert_ne!(cloned.password, "raw-password");
}

/// Verifies owned value mutation supports `String`, `Cow`, and `Option`.
#[test]
fn test_redact_value_mut_supports_owned_value_forms() {
    let masking = strict_policy().masking().clone();
    let mut text = String::from("raw-string");
    let mut cow = Cow::Borrowed("raw-cow");
    let mut optional = Some(String::from("raw-option"));

    RedactValueMut::redact_value_in_place(
        &mut text,
        Sensitivity::Secret,
        &masking,
    );
    RedactValueMut::redact_value_in_place(
        &mut cow,
        Sensitivity::Secret,
        &masking,
    );
    RedactValueMut::redact_value_in_place(
        &mut optional,
        Sensitivity::Secret,
        &masking,
    );

    assert_eq!(text, "[strict]");
    assert_eq!(cow, "[strict]");
    assert_eq!(optional.as_deref(), Some("[strict]"));
}

/// Verifies empty and absent values remain unchanged during mutation.
#[test]
fn test_redact_value_mut_preserves_empty_and_absent_values() {
    let masking = strict_policy().masking().clone();
    let mut text = String::new();
    let mut cow = Cow::Borrowed("");
    let mut optional: Option<String> = None;

    RedactValueMut::redact_value_in_place(
        &mut text,
        Sensitivity::Secret,
        &masking,
    );
    RedactValueMut::redact_value_in_place(
        &mut cow,
        Sensitivity::Secret,
        &masking,
    );
    RedactValueMut::redact_value_in_place(
        &mut optional,
        Sensitivity::Secret,
        &masking,
    );

    assert_eq!(text, "");
    assert_eq!(cow, "");
    assert_eq!(optional, None);
}
