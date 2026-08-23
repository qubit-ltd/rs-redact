// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private shared implementation for JSON redaction.

#[cfg(feature = "http")]
mod json_redaction_outcome;
#[cfg(feature = "http")]
mod json_redaction_state;
mod json_structure_seed;
mod json_structure_visitor;
#[cfg(feature = "http")]
mod json_unkeyed_value_policy;
mod redacted_value;
mod value_context;

#[cfg(feature = "http")]
pub(crate) use json_redaction_outcome::JsonRedactionOutcome;
#[cfg(feature = "http")]
pub(crate) use json_redaction_state::JsonRedactionState;
pub(super) use json_structure_seed::JsonStructureSeed;
pub(super) use json_structure_visitor::JsonStructureVisitor;
#[cfg(feature = "http")]
pub(crate) use json_unkeyed_value_policy::JsonUnkeyedValuePolicy;
pub(super) use redacted_value::RedactedValue;
