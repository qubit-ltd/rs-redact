// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for TOML string encoding used by isolated manifests.

mod support;

use std::io::Write;
use std::process::Command;
use std::process::Stdio;

use support::manifest::toml_string;

#[test]
fn test_encoded_manifest_paths_round_trip_through_tomllib() {
    let values = [
        r"C:\work\qubit",
        "a\"b",
        "path with spaces",
        "路径/项目",
        "line\nbreak\ttab\u{0001}",
    ];
    for value in values {
        let manifest = format!("[dependencies]\nfixture = {{ path = {} }}\n", toml_string(value),);
        let script = "import json, sys, tomllib\ndata = tomllib.loads(sys.stdin.read())\nprint(json.dumps(data['dependencies']['fixture']['path'], ensure_ascii=False))\n";
        let mut child = Command::new("python3")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("python3 should be available for tomllib manifest parsing");
        child
            .stdin
            .as_mut()
            .expect("python stdin should be piped")
            .write_all(manifest.as_bytes())
            .expect("manifest should be sent to python stdin");
        let output = child.wait_with_output().expect("python should finish parsing");
        assert!(
            output.status.success(),
            "tomllib rejected manifest {manifest:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let actual: String = serde_json::from_slice(&output.stdout).expect("python should return JSON string");
        assert_eq!(actual, value);
    }
}
