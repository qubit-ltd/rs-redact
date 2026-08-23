// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private state used while rendering an HTTP body.

use super::BodyRenderReason;

/// Describes the outcome class of an HTTP body rendering attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats::http) enum BodyRenderStatus {
    /// No body bytes were present.
    Empty,
    /// A supported structured format was rendered.
    Structured,
    /// Policy allowed the original body text to remain visible.
    PassedThrough,
    /// Fail-closed rendering was selected for the recorded reason.
    Redacted(BodyRenderReason),
    /// The body is binary and is represented without decoding it.
    Binary,
}
