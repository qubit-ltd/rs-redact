// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixed-size pending classification for heuristic argv redaction.

use crate::Sensitivity;

/// Option classification waiting for its separate argv value.
pub(super) enum PendingField {
    /// Classified option sensitivity, cached to avoid retaining its name.
    Classified(Sensitivity),
    /// Non-Unicode argument requiring an opaque secret replacement.
    OpaqueSecret,
}
