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

/// Lazily initialized process-wide snapshot slot, protected for atomic
/// replacement.
static DEFAULT_REDACTOR: OnceLock<RwLock<Redactor>> = OnceLock::new();

/// Returns the process-wide default redactor slot.
///
/// # Returns
///
/// The shared lock, initialized once with the standard redactor.
#[must_use]
#[inline(always)]
pub(super) fn slot() -> &'static RwLock<Redactor> {
    DEFAULT_REDACTOR.get_or_init(|| RwLock::new(Redactor::standard()))
}
