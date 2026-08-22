// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private shared implementation for JSON redaction.

mod json_redaction_outcome;
mod json_redaction_state;
mod json_structure_seed;
mod json_structure_visitor;
mod json_unkeyed_value_policy;

pub(crate) use json_redaction_outcome::JsonRedactionOutcome;
pub(crate) use json_redaction_state::JsonRedactionState;
pub(super) use json_structure_seed::JsonStructureSeed;
pub(super) use json_structure_visitor::JsonStructureVisitor;
pub(crate) use json_unkeyed_value_policy::JsonUnkeyedValuePolicy;
