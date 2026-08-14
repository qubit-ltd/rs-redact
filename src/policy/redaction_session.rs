// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable accounting for one bounded diagnostic redaction event.

use super::DiagnosticBudget;
use super::RedactionPolicy;
use super::internal::FragmentCompletion;
use super::internal::RedactionAdmission;

/// Carries one immutable policy and one mutable budget through a diagnostic
/// event.
#[must_use]
#[derive(Debug)]
pub struct RedactionSession<'policy> {
    policy: &'policy RedactionPolicy,
    budget: DiagnosticBudget,
}

impl<'policy> RedactionSession<'policy> {
    /// Creates diagnostic accounting from `policy`.
    #[inline]
    pub(crate) fn new(policy: &'policy RedactionPolicy) -> Self {
        Self {
            policy,
            budget: DiagnosticBudget::new(policy.limits().diagnostic_event()),
        }
    }

    /// Returns the immutable policy snapshot used by this session.
    #[inline]
    pub const fn policy(&self) -> &'policy RedactionPolicy {
        self.policy
    }

    /// Admits one complete input fragment for bounded rendering.
    pub(crate) fn admit(
        &mut self,
        input_bytes: usize,
        domain_output_limit: usize,
        fallback_bytes: usize,
    ) -> RedactionAdmission {
        self.budget
            .admit(input_bytes, domain_output_limit, fallback_bytes)
    }

    /// Admits output for a nested fragment covered by its parent's input.
    pub(crate) fn admit_precharged_output(
        &mut self,
        domain_output_limit: usize,
    ) -> RedactionAdmission {
        self.budget.admit_precharged(domain_output_limit)
    }

    /// Returns whether an active parent reserved this nested input.
    #[inline(always)]
    pub(crate) fn input_is_precharged(&self) -> bool {
        self.budget.input_is_precharged()
    }

    /// Commits exact output bytes for the active admitted fragment.
    pub(crate) fn commit_output(
        &mut self,
        bytes: usize,
        completion: FragmentCompletion,
    ) {
        self.budget.commit_output(bytes, completion);
    }

    /// Returns the remaining input allowance.
    #[must_use]
    #[inline]
    pub fn remaining_input_bytes(&self) -> usize {
        self.budget.remaining_input_bytes()
    }

    /// Returns the remaining output allowance.
    #[must_use]
    #[inline]
    pub fn remaining_output_bytes(&self) -> usize {
        self.budget.remaining_output_bytes()
    }

    /// Returns whether this session is exhausted.
    #[must_use]
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.budget.is_exhausted()
    }
}
