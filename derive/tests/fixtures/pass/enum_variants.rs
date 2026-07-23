// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for every enum variant shape.

use qubit_redact_derive::{Redact, RedactMut};

/// Enum combining named, tuple, and unit variants.
#[derive(Redact, RedactMut)]
enum Event {
    /// Named variant with a sensitive field.
    Named {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple variant with a sensitive and skipped field.
    Tuple(
        #[redact(level = "secret")] String,
        #[redact(skip)] String,
    ),
    /// Unit variant.
    Ready,
}

/// Keeps the supported type reachable.
fn main() {
    let _ = Event::Named {
        secret: String::new(),
    };
    let _ = Event::Tuple(String::new(), String::new());
    let _ = Event::Ready;
}
