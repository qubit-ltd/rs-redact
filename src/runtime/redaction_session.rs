// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable accounting for one bounded diagnostic redaction event.

use super::DiagnosticBudget;
use super::DomainRedactionBudget;
use super::DomainTruncation;
use super::DomainTruncationCheckpoint;
use super::internal::FragmentCompletion;
use super::internal::RedactionAdmission;
use crate::policy::DomainTraversalAdmission;
use crate::policy::DomainValueAdmission;
use crate::policy::DomainValueScope;
use crate::policy::RedactionPolicy;
use crate::runtime::DomainValueBudgetAdmission;

/// Carries one immutable policy and one mutable budget through a diagnostic
/// event.
#[derive(Debug)]
pub struct RedactionSession<'policy> {
    policy: &'policy RedactionPolicy,
    budget: DiagnosticBudget,
    pub(super) domain_budget: DomainRedactionBudget,
}

impl<'policy> RedactionSession<'policy> {
    /// Creates diagnostic accounting from `policy`.
    #[must_use]
    #[inline]
    pub(crate) fn new(policy: &'policy RedactionPolicy) -> Self {
        Self {
            policy,
            budget: DiagnosticBudget::new(policy.limits().diagnostic_event()),
            domain_budget: DomainRedactionBudget::new(policy.limits().domain()),
        }
    }

    /// Returns the immutable policy snapshot used by this session.
    #[inline]
    #[must_use]
    pub const fn policy(&self) -> &'policy RedactionPolicy {
        self.policy
    }

    /// Charges and enters one domain value under the shared structure budget.
    ///
    /// Admission first honors permanent traversal closure, then checks active
    /// depth, and finally consumes one cumulative node. An entered value
    /// returns an RAII [`DomainValueScope`] that restores only active depth on
    /// drop. [`DomainValueAdmission::DepthLimitReached`] rejects just the
    /// current branch, while [`DomainValueAdmission::TraversalLimitReached`]
    /// means no later domain value may be accessed in this session.
    #[must_use]
    pub fn enter_domain_value<'session>(
        &'session mut self,
    ) -> DomainValueAdmission<'session, 'policy> {
        let checkpoint = self.domain_truncation_checkpoint();
        let admission = self.domain_budget.enter_value();
        debug_assert!(match admission {
            DomainValueBudgetAdmission::Entered => {
                self.domain_truncation_since(checkpoint)
                    == DomainTruncation::None
            }
            DomainValueBudgetAdmission::DepthLimitReached => {
                self.domain_truncation_since(checkpoint)
                    == DomainTruncation::Depth
            }
            DomainValueBudgetAdmission::TraversalLimitReached => true,
        });
        match admission {
            DomainValueBudgetAdmission::Entered => {
                DomainValueAdmission::Entered(DomainValueScope::new(self))
            }
            DomainValueBudgetAdmission::DepthLimitReached => {
                DomainValueAdmission::DepthLimitReached
            }
            DomainValueBudgetAdmission::TraversalLimitReached => {
                DomainValueAdmission::TraversalLimitReached
            }
        }
    }

    /// Returns a checkpoint for detecting later domain traversal truncation.
    #[inline(always)]
    pub(crate) const fn domain_truncation_checkpoint(
        &self,
    ) -> DomainTruncationCheckpoint {
        self.domain_budget.truncation_checkpoint()
    }

    /// Classifies domain truncation recorded after `checkpoint`.
    #[inline(always)]
    pub(crate) const fn domain_truncation_since(
        &self,
        checkpoint: DomainTruncationCheckpoint,
    ) -> DomainTruncation {
        self.domain_budget.truncation_since(checkpoint)
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

    /// Admits pure domain output without covering nested adapter input.
    ///
    /// This frame participates in nested output deduplication, but any adapter
    /// invoked beneath it must still reserve its exact source bytes before
    /// parsing, resolving, or formatting that source.
    pub(crate) fn admit_output_only(
        &mut self,
        domain_output_limit: usize,
    ) -> RedactionAdmission {
        self.budget.admit_output_only(domain_output_limit)
    }

    /// Charges one domain field before its value is accessed.
    #[inline]
    pub(crate) fn admit_domain_field(&mut self) -> DomainTraversalAdmission {
        self.domain_budget.admit_field()
    }

    /// Charges one domain collection item before its iterator advances.
    #[inline]
    pub(crate) fn admit_domain_collection_item(
        &mut self,
    ) -> DomainTraversalAdmission {
        self.domain_budget.admit_collection_item()
    }

    /// Releases one active domain-value depth while preserving cumulative
    /// charges.
    #[inline]
    pub(crate) fn leave_domain_value(&mut self) {
        self.domain_budget.leave_value();
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
