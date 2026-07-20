// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable HTTP redaction policy, bounded body input, and safe results.

mod body_budget;
mod body_budget_error;
mod body_capture;
mod body_capture_error;
mod body_redaction;
mod body_redaction_reason;
mod body_redaction_status;
mod http_redaction_policy;
mod http_redaction_policy_builder;

pub use crate::adapter::{
    TextBodyPolicy,
    UnkeyedJsonValuePolicy,
    UrlPathPolicy,
};
pub use body_budget::BodyBudget;
pub use body_budget_error::BodyBudgetError;
pub use body_capture::BodyCapture;
pub use body_capture_error::BodyCaptureError;
pub use body_redaction::BodyRedaction;
pub use body_redaction_reason::BodyRedactionReason;
pub use body_redaction_status::BodyRedactionStatus;
pub use http_redaction_policy::HttpRedactionPolicy;
pub use http_redaction_policy_builder::HttpRedactionPolicyBuilder;
