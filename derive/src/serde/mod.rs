// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redacted Serde implementation generation.

mod entry;
mod r#enum;
mod field;
mod field_access;
mod internal;
mod naming;
mod r#struct;

/// Generates the redacted Serde implementation for one derive input.
pub(crate) use entry::expand;
