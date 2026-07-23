// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixtures for malformed field controls.

use qubit_redact_derive::Redact;

/// Field controls must use list syntax.
#[derive(Redact)]
struct PathAttribute {
    /// Invalid path-style helper.
    #[redact]
    value: String,
}

/// Sensitivity levels require an assigned string literal.
#[derive(Redact)]
struct MissingLevelValue {
    /// Invalid bare level.
    #[redact(level)]
    value: String,
}

/// Skip is a bare control.
#[derive(Redact)]
struct AssignedSkip {
    /// Invalid assigned skip.
    #[redact(skip = true)]
    value: String,
}

/// Nested is a bare control.
#[derive(Redact)]
struct ParenthesizedNested {
    /// Invalid parenthesized nested control.
    #[redact(nested())]
    value: String,
}

/// Map is a bare control.
#[derive(Redact)]
struct AssignedMap {
    /// Invalid assigned map control.
    #[redact(map = true)]
    value: String,
}

/// Invalid enum fields exercise variant error propagation.
#[derive(Redact)]
enum InvalidVariantField {
    /// Named variant with an invalid field control.
    Named {
        /// Empty controls are rejected.
        #[redact()]
        value: String,
    },
}

/// Keeps every invalid type reachable.
fn main() {}
