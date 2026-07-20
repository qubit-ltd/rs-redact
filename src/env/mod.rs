// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redaction adapters for environment-variable diagnostics.

mod env_redactor;
mod redacted_env_pair;

pub use env_redactor::EnvRedactor;
pub use redacted_env_pair::RedactedEnvPair;
