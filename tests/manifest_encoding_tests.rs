// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for TOML string encoding used by isolated manifests.

mod support;

use support::manifest::toml_string;

#[test]
fn test_encoded_manifest_paths_round_trip_through_toml_parser() {
    let values = [
        r"C:\work\qubit",
        "a\"b",
        "path with spaces",
        "路径/项目",
        "line\nbreak\ttab\u{0001}",
    ];
    for value in values {
        let manifest = format!("[dependencies]\nfixture = {{ path = {} }}\n", toml_string(value),);
        let parsed: toml::Value = toml::from_str(&manifest)
            .unwrap_or_else(|error| panic!("TOML parser rejected manifest {manifest:?}: {error}"));
        let actual = parsed
            .get("dependencies")
            .and_then(|dependencies| dependencies.get("fixture"))
            .and_then(|fixture| fixture.get("path"))
            .and_then(toml::Value::as_str)
            .expect("fixture path should be a TOML string");
        assert_eq!(actual, value);
    }
}
