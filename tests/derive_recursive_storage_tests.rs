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

#[derive(Debug)]
struct RecursiveDebugChild {
    leaf: String,
}

#[derive(Debug, Redact)]
struct RecursiveDebugStorage {
    root: String,
    leaf: std::collections::BTreeMap<String, String>,
    shared: std::rc::Rc<String>,
    boxed: Box<RecursiveDebugChild>,
}

#[test]
fn test_recursive_debug_storage_uses_plain_debug_path() {
    let value = RecursiveDebugStorage {
        root: "root".to_owned(),
        leaf: [("leaf".to_owned(), "value".to_owned())].into(),
        shared: std::rc::Rc::new("shared".to_owned()),
        boxed: Box::new(RecursiveDebugChild {
            leaf: "boxed".to_owned(),
        }),
    };
    assert_eq!(value.boxed.leaf, "boxed");
    let rendered = format!("{value:?}");
    assert!(
        rendered.contains("root"),
        "root field should remain visible: {rendered}"
    );
    assert!(rendered.contains("leaf"), "map child should remain visible: {rendered}");
    assert!(
        rendered.contains("shared"),
        "Rc child should remain visible: {rendered}"
    );
    assert!(
        rendered.contains("boxed"),
        "supported Box recursion should remain visible: {rendered}"
    );
}
