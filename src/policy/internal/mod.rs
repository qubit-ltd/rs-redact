// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal field-name canonicalization and candidate generation.

mod field_name;

pub(crate) use field_name::{
    canonical_field_candidates,
    canonicalize_field_name,
};
