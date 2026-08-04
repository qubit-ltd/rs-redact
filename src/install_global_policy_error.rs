// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
// =============================================================================
//! Error returned when a process-wide policy is installed twice.

use std::{
    error::Error,
    fmt,
};

use crate::RedactionPolicy;

/// Owns the policy that could not be installed because a global policy was
/// already installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallGlobalPolicyError(pub(crate) RedactionPolicy);

impl InstallGlobalPolicyError {
    /// Returns the policy that was rejected by the global slot.
    #[must_use = "use the rejected policy or drop it explicitly"]
    pub fn into_policy(self) -> RedactionPolicy {
        self.0
    }
}

impl fmt::Display for InstallGlobalPolicyError {
    /// Writes the stable installation error message.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the global redaction policy is already installed")
    }
}

impl Error for InstallGlobalPolicyError {}
