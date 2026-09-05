// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private functional modules for redacted Serde expansion.

mod adjacently_tagged;
mod externally_tagged;
mod internally_tagged;
mod untagged;
mod variant_fields;

pub(super) use adjacently_tagged::adjacent_variant_arm;
pub(super) use externally_tagged::external_variant_arm;
pub(super) use internally_tagged::internal_variant_arm;
pub(super) use untagged::untagged_variant_arm;
