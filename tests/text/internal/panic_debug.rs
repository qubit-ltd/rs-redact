// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! A test value that panics whenever debug formatting is attempted.

// qubit-style: allow test-file-name

use std::fmt::{Debug, Formatter, Result};

/// Proves redacted debug wrappers never invoke the wrapped value's formatter.
pub(crate) struct PanicDebug;

impl Debug for PanicDebug {
    /// Rejects every attempt to format this value.
    ///
    /// # Parameters
    ///
    /// - `_formatter`: The formatter that must never receive this value.
    ///
    /// # Returns
    ///
    /// This method never returns.
    ///
    /// # Panics
    ///
    /// Always panics to expose an incorrect delegation by the wrapper.
    fn fmt(&self, _formatter: &mut Formatter<'_>) -> Result {
        panic!("the wrapped Debug implementation must not be called")
    }
}
