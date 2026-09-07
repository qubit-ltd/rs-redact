// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public format tests grouped by their production namespace.

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "json")]
mod json;
mod process;
#[cfg(feature = "uri")]
mod uri;
