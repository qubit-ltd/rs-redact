// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private helper types for mirrored text integration tests.

mod no_debug;
mod panic_debug;

pub(super) use no_debug::NoDebug;
pub(super) use panic_debug::PanicDebug;
