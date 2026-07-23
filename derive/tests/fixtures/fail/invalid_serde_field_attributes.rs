// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixtures for malformed Serde field controls.

use qubit_redact_derive::Redact;

/// Serde field controls must use list syntax.
#[derive(Redact)]
#[redact(serde)]
struct PathAttribute {
    /// Invalid path-style helper.
    #[serde]
    value: String,
}

/// Field renames may be specified once.
#[derive(Redact)]
#[redact(serde)]
struct DuplicateRename {
    /// Repeated rename.
    #[serde(rename = "first", rename = "second")]
    value: String,
}

/// Skip controls must be bare.
#[derive(Redact)]
#[redact(serde)]
struct AssignedSkip {
    /// Invalid assigned skip.
    #[serde(skip = true)]
    value: String,
}

/// Equivalent skip controls conflict.
#[derive(Redact)]
#[redact(serde)]
struct DuplicateSkip {
    /// Repeated skip.
    #[serde(skip)]
    #[serde(skip_serializing)]
    value: String,
}

/// Conditional skip predicates may be specified once.
#[derive(Redact)]
#[redact(serde)]
struct DuplicatePredicate {
    /// Repeated predicate.
    #[serde(
        skip_serializing_if = "String::is_empty",
        skip_serializing_if = "String::is_empty"
    )]
    value: String,
}

/// Structural Serde controls are outside the redacted allowlist.
#[derive(Redact)]
#[redact(serde)]
struct UnsupportedControl {
    /// Flatten could bypass the generated redaction shape.
    #[serde(flatten)]
    value: String,
}

/// Invalid tuple fields exercise positional error propagation.
#[derive(Redact)]
#[redact(serde)]
struct InvalidTuple(#[serde] String);

/// Rename controls require an assigned value.
#[derive(Redact)]
#[redact(serde)]
struct MissingRenameValue {
    /// Rename without `= "..."`.
    #[serde(rename)]
    value: String,
}

/// Rename controls require string literals.
#[derive(Redact)]
#[redact(serde)]
struct NonStringRename {
    /// Rename using an integer literal.
    #[serde(rename = 7)]
    value: String,
}

/// Conditional skip controls require an assigned value.
#[derive(Redact)]
#[redact(serde)]
struct MissingPredicateValue {
    /// Predicate without `= "..."`.
    #[serde(skip_serializing_if)]
    value: String,
}

/// Conditional skip controls require string literals.
#[derive(Redact)]
#[redact(serde)]
struct NonStringPredicate {
    /// Predicate using an integer literal.
    #[serde(skip_serializing_if = 7)]
    value: String,
}

/// Conditional skip controls require valid Rust paths.
#[derive(Redact)]
#[redact(serde)]
struct InvalidPredicatePath {
    /// Predicate string that cannot parse as a path.
    #[serde(skip_serializing_if = "not a path")]
    value: String,
}

/// Keeps every invalid type reachable.
fn main() {}
