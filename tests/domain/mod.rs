// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mirrored integration tests for domain-object redaction APIs.

mod bounded_redacted_display_tests;
mod derive_attribute_tests;
mod internal;
#[cfg(feature = "json")]
mod json_field_tests;
mod map_tests;
mod mod_tests;
mod redact_map_serialize_tests;
mod redact_map_value_mut_tests;
mod redact_map_value_tests;
mod redact_mut_tests;
mod redact_serialize_tests;
mod redact_tests;
mod redact_value_mut_tests;
mod redact_value_tests;
mod redacted_keyed_map_tests;
mod redacted_keyed_value_tests;
mod redacted_map_tests;
mod redacted_tests;
mod redacted_value_tests;
#[cfg(feature = "serde")]
mod serde_tests;
