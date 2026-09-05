// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixture exercising Serde self-resolution in a crate named `serde`.

use qubit_redact_derive::Redact;
pub use serde_impl::*;

/// Serde traits re-exported at the crate root remain reachable by generated code.
#[derive(Redact)]
#[redact(serde)]
struct Record(String);

/// Keeps the invalid type reachable.
fn main() {}
