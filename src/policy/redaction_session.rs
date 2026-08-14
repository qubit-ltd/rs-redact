// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable accounting for one bounded diagnostic redaction event.

use qubit_budget::ResourceBudget;

use super::InputOutputLimit;
use super::RedactionPolicy;
use super::internal::FragmentCompletion;
use super::internal::RedactionAdmission;

/// Resources charged while rendering one redaction event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedactionResource {
    /// Complete source bytes inspected by one redaction operation.
    Input,
    /// Complete log-safe bytes emitted by one redaction operation.
    Output,
    /// Bytes materialized by generated masks inside a bounded renderer.
    Mask,
}

/// Mutable input/output accounting for one redaction event.
#[must_use]
#[derive(Debug)]
pub(crate) struct DiagnosticBudget {
    input_budget: ResourceBudget<RedactionResource, usize>,
    output_budget: ResourceBudget<RedactionResource, usize>,
    input_closed: bool,
    output_closed: bool,
    admitted_output: Vec<AdmittedOutput>,
}

#[derive(Debug)]
struct AdmittedOutput {
    max_output_bytes: usize,
    remaining_output_bytes: usize,
}

impl DiagnosticBudget {
    /// Creates runtime accounting from an immutable input/output limit.
    #[must_use = "retain the runtime budget for accounting"]
    #[inline]
    pub(crate) fn new(limit: InputOutputLimit) -> Self {
        Self {
            input_budget: ResourceBudget::new(RedactionResource::Input, limit.max_input_bytes()),
            output_budget: ResourceBudget::new(RedactionResource::Output, limit.max_output_bytes()),
            input_closed: false,
            output_closed: false,
            admitted_output: Vec::new(),
        }
    }

    /// Admits a complete input fragment before any source inspection.
    pub(crate) fn admit(
        &mut self,
        input_bytes: usize,
        domain_output_limit: usize,
        fallback_bytes: usize,
    ) -> RedactionAdmission {
        if input_bytes == usize::MAX {
            return self.reject_input(fallback_bytes);
        }
        if !self.admitted_output.is_empty() {
            return self.admit_precharged(domain_output_limit);
        }
        if self.output_closed || self.output_budget.remaining() == 0 {
            self.output_closed = true;
            return RedactionAdmission::Exhausted;
        }
        if self.input_closed || self.input_budget.try_consume(input_bytes).is_err() {
            return self.reject_input(fallback_bytes);
        }
        let max_output_bytes = domain_output_limit.min(self.output_budget.remaining());
        self.admitted_output.push(AdmittedOutput {
            max_output_bytes,
            remaining_output_bytes: self.output_budget.remaining(),
        });
        RedactionAdmission::Render { max_output_bytes }
    }

    /// Rejects unmeasurable or over-budget input and emits only its fallback.
    fn reject_input(&mut self, fallback_bytes: usize) -> RedactionAdmission {
        self.input_closed = true;
        if !self.output_closed
            && self.output_budget.remaining() != 0
            && self.output_budget.try_consume(fallback_bytes).is_ok()
        {
            self.output_closed = self.output_budget.remaining() == 0;
            return RedactionAdmission::Fallback;
        }
        self.output_closed = true;
        RedactionAdmission::Exhausted
    }

    /// Admits nested output whose complete input was reserved by its parent.
    fn admit_precharged(&mut self, domain_output_limit: usize) -> RedactionAdmission {
        if self.output_closed || self.output_budget.remaining() == 0 {
            self.output_closed = true;
            return RedactionAdmission::Exhausted;
        }
        let max_output_bytes = domain_output_limit.min(self.output_budget.remaining());
        self.admitted_output.push(AdmittedOutput {
            max_output_bytes,
            remaining_output_bytes: self.output_budget.remaining(),
        });
        RedactionAdmission::Render { max_output_bytes }
    }

    /// Returns whether an active parent already reserved nested input.
    #[inline(always)]
    fn input_is_precharged(&self) -> bool {
        !self.admitted_output.is_empty()
    }

    /// Commits exact emitted bytes for one previously admitted fragment.
    pub(crate) fn commit_output(&mut self, bytes: usize, completion: FragmentCompletion) {
        let admitted = self
            .admitted_output
            .pop()
            .expect("output must be admitted before it is committed");
        assert!(
            bytes <= admitted.max_output_bytes,
            "committed output exceeds the admitted fragment maximum"
        );
        let nested_bytes = admitted
            .remaining_output_bytes
            .saturating_sub(self.output_budget.remaining());
        let uncommitted_bytes = bytes.saturating_sub(nested_bytes);
        self.output_budget
            .try_consume(uncommitted_bytes)
            .expect("admitted output must fit the shared session budget");
        match completion {
            FragmentCompletion::Complete | FragmentCompletion::DomainTruncated => {}
            FragmentCompletion::SessionTruncated => {
                self.output_closed = true;
            }
        }
    }

    /// Returns the input bytes still available for inspection.
    #[inline]
    pub(crate) fn remaining_input_bytes(&self) -> usize {
        self.input_budget.remaining()
    }

    /// Returns the output bytes still available for rendering.
    #[inline]
    pub(crate) fn remaining_output_bytes(&self) -> usize {
        if self.output_closed {
            0
        } else {
            self.output_budget.remaining()
        }
    }

    /// Returns whether this event can no longer accept input or output.
    #[must_use]
    #[inline]
    pub(crate) fn is_exhausted(&self) -> bool {
        self.output_closed
            || self.output_budget.remaining() == 0
            || (!self.input_is_precharged()
                && (self.input_closed || self.input_budget.remaining() == 0))
    }
}

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
    pub(crate) fn commit_output(&mut self, bytes: usize, completion: FragmentCompletion) {
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
