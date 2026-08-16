// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Error returned when a process-wide policy is installed twice.

use std::error::Error;
use std::fmt;

use crate::RedactionPolicy;

/// Owns the policy that could not be installed because a global policy was
/// already installed.
///
/// The rejected policy is stored out of line so the error does not enlarge
/// every successful installation result. [`Self::into_policy`] returns the
/// original owned policy without cloning it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallGlobalPolicyError(Box<RedactionPolicy>);

impl InstallGlobalPolicyError {
    #[must_use]
    /// Creates an error that owns the rejected policy without enlarging every
    /// installation result.
    pub(crate) fn new(policy: RedactionPolicy) -> Self {
        Self(Box::new(policy))
    }

    /// Returns the policy that was rejected by the global slot.
    ///
    /// This consumes the error and moves the original policy out of its
    /// internal allocation without cloning it.
    #[inline(always)]
    #[must_use]
    pub fn into_policy(self) -> RedactionPolicy {
        *self.0
    }
}

impl fmt::Display for InstallGlobalPolicyError {
    /// Writes the stable installation error message.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the global redaction policy is already installed")
    }
}

impl Error for InstallGlobalPolicyError {}
