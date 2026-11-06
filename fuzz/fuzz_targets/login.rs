// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Input record for consumer projection fuzzing.

use qubit_redact::Redact;

/// Minimal consumer record with one visible field and one secret field.
#[derive(Redact)]
#[redact(serde)]
pub(super) struct Login {
    /// Public diagnostic label retained by the projection.
    pub(super) label: String,
    /// Secret payload that must never appear in redacted output.
    #[redact(level = "secret")]
    pub(super) password: String,
}
