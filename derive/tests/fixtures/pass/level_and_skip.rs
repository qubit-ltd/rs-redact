// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for explicit level masking and bound-free skipped fields.

use qubit_redact::Redact as RedactTrait;
use qubit_redact_derive::Redact;

/// Marker that intentionally has no `Debug` implementation.
struct NotDebug;

/// Named struct accepted by the field-attribute parser.
#[derive(Redact)]
struct Record {
    /// Explicitly sensitive text.
    #[redact(level = "secret")]
    password: String,
    /// Omitted field that must not require a formatting bound.
    #[redact(skip)]
    cache: NotDebug,
}

/// Builds and formats the derived view.
fn main() {
    let value = Record {
        password: "secret".to_owned(),
        cache: NotDebug,
    };
    let _ = &value.cache;
    let _ = format!("{:?}", value.redacted());
}
