// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internal domain serialization support.

#[cfg(feature = "serde")]
mod internally_tagged_serializer_tests;
mod mod_tests;
mod nested_tests;
mod redacted_serialize_tests;
