// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Executable wire-shape coverage for generated structured Serde support.

#![cfg(all(feature = "derive", feature = "serde"))]

use std::sync::Mutex;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

static APPLICATION_DEFAULT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Redact)]
#[redact(serde)]
struct WireRecord {
    visible: String,
    #[redact(level = "secret")]
    number: u32,
    #[redact(skip)]
    hidden: String,
    #[serde(skip)]
    serde_hidden: String,
}

#[test]
fn structured_serde_masks_numeric_leaves_as_strings_and_preserves_shape() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let previous = Redactor::replace_application_default(Redactor::standard());
    let encoded = serde_json::to_value(WireRecord {
        visible: "shown".to_owned(),
        number: 7,
        hidden: "redact-hidden".to_owned(),
        serde_hidden: "serde-hidden".to_owned(),
    })
    .expect("structured serialization");

    assert_eq!(encoded["visible"], "shown");
    assert!(encoded["number"].is_string());
    assert_ne!(encoded["number"], "7");
    assert!(encoded.get("hidden").is_none());
    assert!(encoded.get("serde_hidden").is_none());

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn disabled_structured_serde_restores_redact_fields_but_not_serde_skips() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let previous = Redactor::replace_application_default(Redactor::new(RedactionPolicy::disabled()));
    let encoded = serde_json::to_value(WireRecord {
        visible: "shown".to_owned(),
        number: 7,
        hidden: "redact-hidden".to_owned(),
        serde_hidden: "serde-hidden".to_owned(),
    })
    .expect("disabled structured serialization");

    assert_eq!(encoded["visible"], "shown");
    assert_eq!(encoded["number"], 7);
    assert_eq!(encoded["hidden"], "redact-hidden");
    assert!(encoded.get("serde_hidden").is_none());

    let _ = Redactor::replace_application_default(previous);
}
