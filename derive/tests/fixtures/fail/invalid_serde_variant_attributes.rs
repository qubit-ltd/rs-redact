// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixtures for malformed Serde variant controls.

use qubit_redact_derive::Redact;

/// Serde variant controls must use list syntax.
#[derive(Redact)]
#[redact(serde)]
enum PathAttribute {
    /// Invalid path-style helper.
    #[serde]
    Value,
}

/// Variant renames may be specified once.
#[derive(Redact)]
#[redact(serde)]
enum DuplicateRename {
    /// Repeated rename.
    #[serde(rename = "first", rename = "second")]
    Value,
}

/// Variant field rename rules may be specified once.
#[derive(Redact)]
#[redact(serde)]
enum DuplicateRenameAll {
    /// Repeated rename rule.
    #[serde(rename_all = "camelCase", rename_all = "snake_case")]
    Value {
        /// Named field.
        some_value: String,
    },
}

/// Variant skip controls must be bare.
#[derive(Redact)]
#[redact(serde)]
enum AssignedSkip {
    /// Invalid assigned skip.
    #[serde(skip = true)]
    Value,
}

/// Equivalent variant skip controls conflict.
#[derive(Redact)]
#[redact(serde)]
enum DuplicateSkip {
    /// Repeated skip.
    #[serde(skip, skip_serializing)]
    Value,
}

/// Structural variant controls are outside the redacted allowlist.
#[derive(Redact)]
#[redact(serde)]
enum UnsupportedControl {
    /// Other changes value lookup semantics.
    #[serde(other)]
    Value,
}

/// Keeps every invalid type reachable.
fn main() {}
