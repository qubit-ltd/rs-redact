// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stable data-model types shared by policy and format adapters.

mod field_redaction;
mod pass_through_reason;

pub use field_redaction::FieldRedaction;
pub use pass_through_reason::PassThroughReason;

pub use crate::policy::FieldClassification;
pub use crate::policy::FieldMatchKind;
pub use crate::policy::FieldNameMatching;
pub use crate::policy::Sensitivity;
