// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! RAII release of structured serialization depth.

use super::redact_serialize_scope::leave_node;

/// Releases one admitted node even when a user serializer unwinds.
pub(super) struct SerdeNodeGuard;

impl Drop for SerdeNodeGuard {
    /// Restores the active scope's depth.
    fn drop(&mut self) {
        leave_node();
    }
}
