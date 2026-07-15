// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for structured object sanitization adapters.

#[cfg(feature = "core")]
mod argv_tests;
#[cfg(feature = "core")]
mod env_tests;
#[cfg(feature = "web")]
mod form_urlencoded_tests;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "web")]
mod url_tests;
