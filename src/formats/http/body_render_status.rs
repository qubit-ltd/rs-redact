// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private state used while rendering an HTTP body.

use super::BodyRenderReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats::http) enum BodyRenderStatus {
    Empty,
    Structured,
    PassedThrough,
    Redacted(BodyRenderReason),
    Binary,
}
