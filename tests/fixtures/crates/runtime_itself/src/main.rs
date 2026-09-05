// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixture exercising runtime self-resolution before attribute validation.

use qubit_redact_derive::Redact;

/// Invalid control is reached only after runtime self-resolution succeeds.
#[derive(Redact)]
#[redact(unknown)]
struct Record;

/// Keeps the invalid type reachable.
fn main() {}
