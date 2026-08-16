// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared execution-time accounting for bounded redaction operations.

mod diagnostic_budget;
mod domain_budget;
mod internal;
mod redaction_session;

pub(crate) use diagnostic_budget::DiagnosticBudget;
pub(crate) use domain_budget::DomainRedactionBudget;
pub(crate) use domain_budget::DomainTruncation;
pub(crate) use domain_budget::DomainTruncationCheckpoint;
pub(crate) use domain_budget::DomainValueBudgetAdmission;
pub(crate) use internal::FragmentCompletion;
pub(crate) use internal::RedactionAdmission;
pub use redaction_session::RedactionSession;
