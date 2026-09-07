// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! RAII preservation of the caller's budget across ordinary Serde callbacks.

use super::redact_serialize_scope::enter_raw_serializer;
use super::redact_serialize_scope::leave_raw_serializer;

/// Keeps reentrant serializers from replacing the active resource allowance.
pub(super) struct SerdeRawGuard {
    /// Whether an existing scope was pinned.
    active: bool,
}

impl SerdeRawGuard {
    /// Pins the existing scope, if one is present.
    ///
    /// # Returns
    ///
    /// An active pin when a budget exists, otherwise an inert guard.
    /// Dropping an active guard releases exactly the pin acquired here.
    #[must_use]
    #[inline(always)]
    pub(super) fn new() -> Self {
        Self {
            active: enter_raw_serializer(),
        }
    }
}

impl Drop for SerdeRawGuard {
    /// Releases only the raw-serializer pin acquired by this guard.
    fn drop(&mut self) {
        if self.active {
            leave_raw_serializer();
        }
    }
}
