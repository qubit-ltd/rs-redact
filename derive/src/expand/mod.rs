// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public entry points for redaction derive expansion.

pub(crate) mod assertions;
mod entry;
mod format;
mod redact;

pub(crate) use entry::expand;
