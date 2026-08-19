// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Process-wide application-default redactor snapshot.

use std::sync::OnceLock;
use std::sync::RwLock;

use super::Redactor;

static DEFAULT_REDACTOR: OnceLock<RwLock<Redactor>> = OnceLock::new();

/// Returns the process-wide default redactor slot.
pub(super) fn slot() -> &'static RwLock<Redactor> {
    DEFAULT_REDACTOR.get_or_init(|| RwLock::new(Redactor::standard()))
}
