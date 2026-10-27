// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Derive-only coverage for recursive debug storage.

#![cfg(feature = "derive")]

use qubit_redact::Redact;

#[derive(Debug, Redact)]
struct RecursiveDebugChild {
    leaf: String,
}

#[derive(Redact)]
struct RecursiveDebugStorage {
    root: String,
    leaf: std::collections::BTreeMap<String, String>,
    shared: std::rc::Rc<String>,
    boxed: Box<RecursiveDebugChild>,
}

#[test]
fn test_recursive_redaction_storage_preserves_field_structure_and_values() {
    let value = RecursiveDebugStorage {
        root: "probe-root-17".to_owned(),
        leaf: [("probe-map-key-29".to_owned(), "probe-map-value-31".to_owned())].into(),
        shared: std::rc::Rc::new("probe-rc-37".to_owned()),
        boxed: Box::new(RecursiveDebugChild {
            leaf: "probe-box-41".to_owned(),
        }),
    };
    let output = qubit_redact::Redactor::standard().redact_text(&value);
    assert_eq!(
        output.summary().completion(),
        qubit_redact::RedactionCompletion::Complete
    );
    let rendered = output.text().as_str();
    for expected in [
        "RecursiveDebugStorage",
        "root",
        "leaf",
        "shared",
        "boxed",
        "probe-root-17",
        "probe-map-key-29",
        "probe-map-value-31",
        "probe-rc-37",
        "probe-box-41",
    ] {
        assert!(rendered.contains(expected), "missing {expected:?}: {rendered}");
    }
}
