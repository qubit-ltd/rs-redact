// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
// =============================================================================
//! Operation-scoped mutable accounting for bounded redaction.
// qubit-style: allow multiple-public-types

use std::cell::RefCell;

use super::{
    InputOutputLimit,
    RedactionPolicy,
};

/// Mutable input/output accounting for one redaction event.
///
/// A budget is intentionally not cloneable. Callers must pass the same
/// instance through every component that contributes to one diagnostic
/// rendering so that a child cannot reset the parent's allowance.
#[must_use]
#[derive(Debug)]
pub struct DiagnosticBudget {
    remaining_input_bytes: usize,
    remaining_output_bytes: usize,
    input_exhausted: bool,
    output_exhausted: bool,
}

impl DiagnosticBudget {
    /// Creates runtime accounting from an immutable input/output limit.
    #[must_use = "retain the runtime budget for accounting"]
    #[inline]
    pub const fn new(limit: InputOutputLimit) -> Self {
        Self {
            remaining_input_bytes: limit.max_input_bytes(),
            remaining_output_bytes: limit.max_output_bytes(),
            input_exhausted: false,
            output_exhausted: false,
        }
    }

    /// Reserves input bytes before inspecting source data.
    #[inline]
    pub fn consume_input(&mut self, bytes: usize) -> bool {
        if self.input_exhausted || bytes > self.remaining_input_bytes {
            self.input_exhausted = true;
            self.remaining_input_bytes = 0;
            return false;
        }
        self.remaining_input_bytes -= bytes;
        if self.remaining_input_bytes == 0 {
            self.input_exhausted = true;
        }
        true
    }

    /// Reserves output bytes before writing a rendered fragment.
    #[inline]
    pub fn consume_output(&mut self, bytes: usize) -> bool {
        if self.output_exhausted || bytes > self.remaining_output_bytes {
            self.output_exhausted = true;
            self.remaining_output_bytes = 0;
            return false;
        }
        self.remaining_output_bytes -= bytes;
        if self.remaining_output_bytes == 0 {
            self.output_exhausted = true;
        }
        true
    }

    /// Returns the input bytes still available for inspection.
    #[must_use]
    #[inline]
    pub const fn remaining_input_bytes(&self) -> usize {
        self.remaining_input_bytes
    }

    /// Returns the output bytes still available for rendering.
    #[must_use]
    #[inline]
    pub const fn remaining_output_bytes(&self) -> usize {
        self.remaining_output_bytes
    }

    /// Returns whether this event can no longer accept input or output.
    #[must_use]
    #[inline]
    pub const fn is_exhausted(&self) -> bool {
        self.input_exhausted || self.output_exhausted
    }
}

/// A local input/output allowance charged to a parent [`DiagnosticBudget`].
#[must_use]
#[derive(Debug)]
pub struct DiagnosticBudgetScope<'a> {
    parent: &'a RefCell<DiagnosticBudget>,
    remaining_input_bytes: usize,
    remaining_output_bytes: usize,
    input_exhausted: bool,
    output_exhausted: bool,
}

impl DiagnosticBudgetScope<'_> {
    /// Reserves input bytes within the local scope and its parent.
    #[inline]
    pub fn consume_input(&mut self, bytes: usize) -> bool {
        if self.input_exhausted || bytes > self.remaining_input_bytes {
            self.input_exhausted = true;
            return false;
        }
        if !self.parent.borrow_mut().consume_input(bytes) {
            self.input_exhausted = true;
            return false;
        }
        self.remaining_input_bytes -= bytes;
        true
    }

    /// Reserves output bytes within the local scope and its parent.
    #[inline]
    pub fn consume_output(&mut self, bytes: usize) -> bool {
        if self.output_exhausted || bytes > self.remaining_output_bytes {
            self.output_exhausted = true;
            return false;
        }
        if !self.parent.borrow_mut().consume_output(bytes) {
            self.output_exhausted = true;
            return false;
        }
        self.remaining_output_bytes -= bytes;
        true
    }

    /// Returns the local input bytes still available.
    #[must_use]
    #[inline]
    pub const fn remaining_input_bytes(&self) -> usize {
        self.remaining_input_bytes
    }

    /// Returns the local output bytes still available.
    #[must_use]
    #[inline]
    pub const fn remaining_output_bytes(&self) -> usize {
        self.remaining_output_bytes
    }

    /// Returns whether this child scope is exhausted.
    #[must_use]
    #[inline]
    pub const fn is_exhausted(&self) -> bool {
        self.input_exhausted || self.output_exhausted
    }
}

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

    /// Reserves output bytes in the shared event budget.
    #[inline]
    pub fn consume_output(&self, bytes: usize) -> bool {
        self.budget.borrow_mut().consume_output(bytes)
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

    /// Creates a local scope charged to this session.
    #[must_use = "retain the scoped budget for accounting"]
    #[inline]
    pub fn scope(&self, limit: InputOutputLimit) -> DiagnosticBudgetScope<'_> {
        DiagnosticBudgetScope {
            parent: &self.budget,
            remaining_input_bytes: limit.max_input_bytes(),
            remaining_output_bytes: limit.max_output_bytes(),
            input_exhausted: false,
            output_exhausted: false,
        }
    }
}
