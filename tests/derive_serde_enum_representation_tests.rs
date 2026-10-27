// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime wire-shape coverage for every supported Serde enum representation.

#![cfg(all(feature = "derive", feature = "serde"))]

use std::sync::Mutex;

use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

static APPLICATION_DEFAULT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Redact)]
#[redact(serde)]
enum External {
    Named {
        #[redact(level = "secret")]
        token: String,
        visible: String,
    },
}

#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum Internal {
    Named {
        #[redact(level = "secret")]
        token: String,
        visible: String,
    },
}

#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "payload")]
enum Adjacent {
    Named {
        #[redact(level = "secret")]
        token: String,
        visible: String,
    },
}

#[derive(Redact)]
#[redact(serde)]
#[serde(untagged)]
enum Untagged {
    Named {
        #[redact(level = "secret")]
        token: String,
        visible: String,
    },
}

/// Checks all four Serde enum representations under the application policy.
#[test]
fn test_all_enum_representations_preserve_their_serde_wire_shape() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let previous = Redactor::replace_application_default(Redactor::standard());

    let external = serde_json::to_value(External::Named {
        token: "raw-external".to_owned(),
        visible: "shown".to_owned(),
    })
    .expect("external representation");
    assert_eq!(
        external,
        serde_json::json!({"Named": {"token": "<redacted>", "visible": "shown"}})
    );

    let internal = serde_json::to_value(Internal::Named {
        token: "raw-internal".to_owned(),
        visible: "shown".to_owned(),
    })
    .expect("internal representation");
    assert_eq!(
        internal,
        serde_json::json!({"kind": "Named", "token": "<redacted>", "visible": "shown"})
    );

    let adjacent = serde_json::to_value(Adjacent::Named {
        token: "raw-adjacent".to_owned(),
        visible: "shown".to_owned(),
    })
    .expect("adjacent representation");
    assert_eq!(
        adjacent,
        serde_json::json!({"kind": "Named", "payload": {"token": "<redacted>", "visible": "shown"}})
    );

    let untagged = serde_json::to_value(Untagged::Named {
        token: "raw-untagged".to_owned(),
        visible: "shown".to_owned(),
    })
    .expect("untagged representation");
    assert_eq!(untagged, serde_json::json!({"token": "<redacted>", "visible": "shown"}));

    let _ = Redactor::replace_application_default(previous);
}
