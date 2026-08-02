// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
// qubit-style: allow source-test-pair
//! Error returned when global redaction configuration is installed twice.

use std::{
    error::Error,
    fmt,
};

/// Error returned when the process-wide redaction configuration is installed
/// twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GlobalRedactionConfigAlreadyInstalled;

impl fmt::Display for GlobalRedactionConfigAlreadyInstalled {
    /// Writes the stable installation error message.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "the global redaction configuration is already installed",
        )
    }
}

impl Error for GlobalRedactionConfigAlreadyInstalled {}
