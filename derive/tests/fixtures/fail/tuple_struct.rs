// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for a tuple struct.

use qubit_redact_derive::Redact;

/// Unsupported unnamed fields.
#[derive(Redact)]
struct Pair(String, String);

/// Keeps the invalid type reachable.
fn main() {}
