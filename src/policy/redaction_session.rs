// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Operation-scoped mutable accounting for bounded redaction.

use std::cell::RefCell;

use super::InputOutputLimit;
use super::RedactionPolicy;

mod budget {
    use qubit_budget::ResourceBudget;
    use qubit_budget::ResourceLimit;

    use super::InputOutputLimit;

    /// Mutable input/output accounting for one redaction event.
    ///
    /// A budget is intentionally not cloneable. Callers must pass the same
    /// instance through every component that contributes to one diagnostic
    /// rendering so that a child cannot reset the parent's allowance.
    #[must_use]
    #[derive(Debug)]
    pub(crate) struct DiagnosticBudget {
        input_budget: ResourceBudget,
        output_budget: ResourceBudget,
        input_exhausted: bool,
        output_exhausted: bool,
    }

    /// Result of charging an eagerly returned diagnostic fragment.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum OutputCharge {
        /// The complete fragment was charged and may be returned.
        Complete,
        /// The complete fragment did not fit, but one fallback marker was
        /// charged.
        Fallback,
        /// Neither the fragment nor its fallback can be emitted within the
        /// budget.
        Exhausted,
    }

    impl DiagnosticBudget {
        /// Creates runtime accounting from an immutable input/output limit.
        #[must_use = "retain the runtime budget for accounting"]
        #[inline]
        pub(crate) const fn new(limit: InputOutputLimit) -> Self {
            Self {
                input_budget: ResourceLimit::new(limit.max_input_bytes())
                    .budget(),
                output_budget: ResourceLimit::new(limit.max_output_bytes())
                    .budget(),
                input_exhausted: false,
                output_exhausted: false,
            }
        }

        /// Reserves input bytes before inspecting source data.
        #[inline]
        pub(crate) fn consume_input(&mut self, bytes: usize) -> bool {
            if self.input_exhausted {
                self.input_budget.exhaust();
                return false;
            }
            if self.input_budget.consume_or_exhaust((), bytes).is_err() {
                self.input_exhausted = true;
                return false;
            }
            if self.input_budget.is_empty() {
                self.input_exhausted = true;
            }
            true
        }

        /// Atomically charges either a complete fragment or its terminal
        /// fallback.
        pub(crate) fn charge_output_or_fallback(
            &mut self,
            bytes: usize,
            fallback_bytes: usize,
        ) -> OutputCharge {
            if !self.output_exhausted
                && self.output_budget.check_additional((), bytes).is_ok()
            {
                self.output_budget
                    .try_consume((), bytes)
                    .expect("output budget check must precede consumption");
                self.output_exhausted = self.output_budget.is_empty();
                return OutputCharge::Complete;
            }
            if !self.output_exhausted
                && self
                    .output_budget
                    .check_additional((), fallback_bytes)
                    .is_ok()
            {
                self.output_budget
                    .try_consume((), fallback_bytes)
                    .expect("fallback budget check must precede consumption");
                self.output_budget.exhaust();
                self.output_exhausted = true;
                return OutputCharge::Fallback;
            }
            self.output_budget.exhaust();
            self.output_exhausted = true;
            OutputCharge::Exhausted
        }

        /// Returns the input bytes still available for inspection.
        #[must_use]
        #[inline]
        pub(crate) const fn remaining_input_bytes(&self) -> usize {
            self.input_budget.remaining()
        }

        /// Returns the output bytes still available for rendering.
        #[must_use]
        #[inline]
        pub(crate) const fn remaining_output_bytes(&self) -> usize {
            self.output_budget.remaining()
        }

        /// Returns whether this event can no longer accept input or output.
        #[must_use]
        #[inline]
        pub(crate) const fn is_exhausted(&self) -> bool {
            self.input_exhausted || self.output_exhausted
        }
    }
}

pub(crate) use budget::DiagnosticBudget;
pub(crate) use budget::OutputCharge;

mod session_kind {
    /// Identifies whether a session is an ordinary operation or a diagnostic
    /// event.
    #[must_use]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RedactionSessionKind {
        /// An independent ordinary redaction operation.
        Operation,
        /// A diagnostic representation with bounded output.
        Diagnostic,
    }
}

pub use session_kind::RedactionSessionKind;

/// Carries one immutable policy and one mutable budget through a redaction
/// operation.
#[must_use]
#[derive(Debug)]
pub struct RedactionSession<'policy> {
    policy: &'policy RedactionPolicy,
    budget: RefCell<DiagnosticBudget>,
    kind: RedactionSessionKind,
}

impl<'policy> RedactionSession<'policy> {
    /// Creates an ordinary operation session from `policy`.
    #[must_use = "retain the operation session for redaction"]
    #[inline]
    pub fn operation(policy: &'policy RedactionPolicy) -> Self {
        Self {
            policy,
            budget: RefCell::new(DiagnosticBudget::new(
                policy.limits().ordinary_operation(),
            )),
            kind: RedactionSessionKind::Operation,
        }
    }

    /// Creates a diagnostic session from `policy`.
    #[must_use = "retain the diagnostic session for redaction"]
    #[inline]
    pub fn diagnostic(policy: &'policy RedactionPolicy) -> Self {
        Self {
            policy,
            budget: RefCell::new(DiagnosticBudget::new(
                policy.limits().diagnostic_event(),
            )),
            kind: RedactionSessionKind::Diagnostic,
        }
    }

    /// Returns the immutable policy snapshot used by this session.
    #[must_use = "use the policy snapshot for redaction"]
    #[inline]
    pub const fn policy(&self) -> &'policy RedactionPolicy {
        self.policy
    }

    /// Returns the kind of operation represented by this session.
    #[must_use = "use the session kind when selecting operation behavior"]
    #[inline]
    pub const fn kind(&self) -> RedactionSessionKind {
        self.kind
    }

    /// Reserves input bytes in the shared event budget.
    #[inline]
    pub fn consume_input(&self, bytes: usize) -> bool {
        self.budget.borrow_mut().consume_input(bytes)
    }

    /// Charges an eager fragment or, if it does not fit, one terminal marker.
    pub(crate) fn charge_output_or_fallback(
        &self,
        bytes: usize,
        fallback_bytes: usize,
    ) -> OutputCharge {
        self.budget
            .borrow_mut()
            .charge_output_or_fallback(bytes, fallback_bytes)
    }

    /// Returns the remaining input allowance.
    #[must_use]
    #[inline]
    pub fn remaining_input_bytes(&self) -> usize {
        self.budget.borrow().remaining_input_bytes()
    }

    /// Returns the remaining output allowance.
    #[must_use]
    #[inline]
    pub fn remaining_output_bytes(&self) -> usize {
        self.budget.borrow().remaining_output_bytes()
    }

    /// Returns whether this session is exhausted.
    #[must_use]
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.budget.borrow().is_exhausted()
    }
}
