// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for structured object sanitization adapters.

mod argv_sanitizer_tests;
mod env_sanitizer_tests;
#[cfg(feature = "web")]
mod form_url_encoded_sanitizer_tests;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "web")]
mod url_sanitizer_tests;
