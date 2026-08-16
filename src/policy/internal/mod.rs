// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal field-name canonicalization and candidate generation.

mod bounded_mask_writer;
mod field_name;
mod redaction_policy_inner;

pub(super) use bounded_mask_writer::BoundedMaskWriter;
pub(crate) use field_name::canonicalize_field_name;
pub(crate) use field_name::visit_canonical_field_candidates;
pub(super) use redaction_policy_inner::RedactionPolicyInner;
