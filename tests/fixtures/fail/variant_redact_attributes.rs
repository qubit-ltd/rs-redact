// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixtures for unsupported variant-level redaction attributes.

use qubit_redact::Redact;

#[derive(Redact)]
enum MisplacedSkip {
    #[redact(skip)]
    Secret(String),
}

#[derive(Redact)]
enum MisplacedLevel {
    #[redact(level = "secret")]
    Secret { value: String },
}

#[derive(Redact)]
enum MisplacedEmpty {
    #[redact()]
    Unit,
}

#[derive(Redact)]
enum MisplacedUnknown {
    #[redact(unknown)]
    Unit,
}

fn main() {}
