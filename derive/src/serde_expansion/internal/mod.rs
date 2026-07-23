// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private functional modules for redacted Serde expansion.

mod adjacently_tagged;
mod entry;
mod enum_expansion;
mod externally_tagged;
mod field_serialization;
mod internally_tagged;
mod naming;
mod struct_expansion;
mod untagged;
mod variant_fields;

pub(crate) use entry::expand;
