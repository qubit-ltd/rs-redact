// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for disabled field handling.

use qubit_redact_derive::Redact;

/// Record with a field that becomes visible when redaction is disabled.
#[derive(Redact)]
#[redact(serde)]
struct Record {
    /// Field masked at the secret level.
    #[redact(level = "secret")]
    number: u32,
    /// Field restored when redaction is disabled.
    #[redact(skip)]
    restored_when_disabled: String,
}

/// Constructs the record to exercise the derive expansion.
fn main() {
    let _ = Record {
        number: 7,
        restored_when_disabled: "raw".to_owned(),
    };
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
