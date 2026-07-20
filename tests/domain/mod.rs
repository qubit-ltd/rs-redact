// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mirrored integration tests for domain-object redaction APIs.

#[cfg(feature = "derive")]
mod derive_attribute_tests;
#[cfg(feature = "derive")]
mod map_tests;
#[cfg(feature = "derive")]
mod nested_tests;
#[cfg(feature = "derive")]
mod redact_mut_tests;
mod redact_value_tests;
mod redacted_tests;
