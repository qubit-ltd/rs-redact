// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Encoding helpers for temporary Cargo manifests.

use std::path::Path;

/// Encodes a string as a TOML basic string literal.
pub fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

/// Encodes a UTF-8 path as a TOML basic string literal.
pub fn toml_path(path: &Path) -> String {
    let value = path.to_str().expect("temporary manifest path must be valid UTF-8");
    toml_string(value)
}
