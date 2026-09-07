// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mirrored integration tests for domain-object redaction APIs.

#[cfg(feature = "serde")]
mod internal;
mod redact_tests;
mod redaction_key_limits_tests;
mod redaction_writer_tests;
