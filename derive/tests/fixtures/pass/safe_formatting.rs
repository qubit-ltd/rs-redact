// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for generated safe `Debug` and `Display` implementations.

use qubit_redact_derive::Redact;

/// Marker that intentionally implements no formatting trait.
struct NoFormatting;

/// Record using both generated formatting implementations.
#[derive(Redact)]
#[redact(debug, display)]
struct Credentials {
    /// Visible field rendered through ordinary `Debug`.
    visible: &'static str,
    /// Secret field rendered through the configured mask.
    #[redact(level = "secret")]
    password: String,
    /// Omitted field that imposes no formatting bound.
    #[redact(skip)]
    ignored: NoFormatting,
}

/// Record proving `display` does not require the original type to implement
/// `Debug` separately.
#[derive(Redact)]
#[redact(display)]
struct DisplayOnly {
    /// Secret value.
    #[redact(level = "secret")]
    secret: String,
}

/// Exercises every generated trait implementation.
fn main() {
    let value = Credentials {
        visible: "visible",
        password: "raw-password".to_owned(),
        ignored: NoFormatting,
    };
    let _ = &value.ignored;
    let _ = format!("{value:?}");
    let _ = format!("{value:#?}");
    let _ = format!("{value}");

    let display_only = DisplayOnly {
        secret: "raw-secret".to_owned(),
    };
    let _ = format!("{display_only}");
}
