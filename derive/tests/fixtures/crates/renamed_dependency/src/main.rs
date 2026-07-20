// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixture for a renamed runtime dependency.

use redaction_runtime::{Redact, RedactionPolicy};

/// Record derived through the dependency alias.
#[derive(Redact)]
struct Record {
    /// Sensitive owned value.
    #[redact(level = "secret")]
    secret: String,
}

/// Exercises generated absolute paths through the alias.
fn main() {
    let value = Record {
        secret: "raw".to_owned(),
    };
    let _ = format!("{:?}", value.redacted_with(&RedactionPolicy::default()));
}
