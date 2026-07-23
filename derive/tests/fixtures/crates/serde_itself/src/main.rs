// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixture exercising Serde self-resolution before attribute validation.

use qubit_redact_derive::Redact;

/// Unsupported control is reached only after Serde self-resolution succeeds.
#[derive(Redact)]
#[redact(serde)]
#[serde(transparent)]
struct Record(String);

/// Keeps the invalid type reachable.
fn main() {}
