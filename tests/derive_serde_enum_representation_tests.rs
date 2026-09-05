// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
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

#[test]
fn all_enum_representations_preserve_their_serde_wire_shape() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let previous = Redactor::replace_application_default(Redactor::standard());

    let external = serde_json::to_value(External::Named {
        token: "raw-external".to_owned(),
        visible: "shown".to_owned(),
    })
    .expect("external representation");
    assert_eq!(external["Named"]["visible"], "shown");
    assert_ne!(external["Named"]["token"], "raw-external");

    let internal = serde_json::to_value(Internal::Named {
        token: "raw-internal".to_owned(),
        visible: "shown".to_owned(),
    })
    .expect("internal representation");
    assert_eq!(internal["kind"], "Named");
    assert_eq!(internal["visible"], "shown");
    assert_ne!(internal["token"], "raw-internal");

    let adjacent = serde_json::to_value(Adjacent::Named {
        token: "raw-adjacent".to_owned(),
        visible: "shown".to_owned(),
    })
    .expect("adjacent representation");
    assert_eq!(adjacent["kind"], "Named");
    assert_eq!(adjacent["payload"]["visible"], "shown");
    assert_ne!(adjacent["payload"]["token"], "raw-adjacent");

    let untagged = serde_json::to_value(Untagged::Named {
        token: "raw-untagged".to_owned(),
        visible: "shown".to_owned(),
    })
    .expect("untagged representation");
    assert_eq!(untagged["visible"], "shown");
    assert_ne!(untagged["token"], "raw-untagged");

    let _ = Redactor::replace_application_default(previous);
}
