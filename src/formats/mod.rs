// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Protocol and process-format adapters layered over the common runtime.

pub mod argv;
pub mod env;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "json")]
pub mod json;
#[cfg(feature = "uri")]
pub mod uri;
