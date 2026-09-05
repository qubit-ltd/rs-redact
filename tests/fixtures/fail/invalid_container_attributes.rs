// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixtures for malformed container controls.

use qubit_redact_derive::Redact;

/// Container control must use list syntax.
#[derive(Redact)]
#[redact]
struct PathAttribute;

/// Empty container controls are rejected.
#[derive(Redact)]
#[redact()]
struct EmptyAttribute;

/// Unknown container controls are rejected.
#[derive(Redact)]
#[redact(format)]
struct UnknownOption;

/// Container controls must be bare identifiers.
#[derive(Redact)]
#[redact(debug = true)]
struct AssignedOption;

/// Parenthesized container controls are rejected.
#[derive(Redact)]
#[redact(display())]
struct ParenthesizedOption;

/// Keeps every invalid type reachable.
fn main() {}
