// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Origin state for an immutable redaction-floor snapshot.

/// Describes how a rules snapshot obtained its redaction floor.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionFloorState {
    /// The builder captured the process-wide floor when it was created.
    GlobalDefault,
    /// A caller explicitly supplied the floor.
    Explicit,
    /// The caller explicitly disabled every floor.
    Disabled,
}
