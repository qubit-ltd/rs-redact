// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable input/output accounting for one redaction event.

use qubit_budget::ResourceBudget;

use super::internal::FragmentCompletion;
use super::internal::RedactionAdmission;
use crate::policy::InputOutputLimit;
use crate::policy::RedactionResource;

// qubit-style: allow type-file-name
/// Mutable input/output accounting for one redaction event.
#[derive(Debug)]
pub(crate) struct DiagnosticBudget {
    input_budget: ResourceBudget<RedactionResource, usize>,
    output_budget: ResourceBudget<RedactionResource, usize>,
    input_closed: bool,
    output_closed: bool,
    admitted_output: Vec<AdmittedOutput>,
}

/// Output reservation and the input admission that created it.
#[derive(Debug)]
struct AdmittedOutput {
    max_output_bytes: usize,
    remaining_output_bytes: usize,
    input_provenance: InputProvenance,
}

/// Describes whether an active output frame reserved nested input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputProvenance {
    /// The frame's input admission covers nested fragment inspection.
    Precharged,
    /// The frame bounds pure domain output and covers no nested input.
    OutputOnly,
}

impl DiagnosticBudget {
    /// Creates runtime accounting from an immutable input/output limit.
    #[must_use]
    #[inline]
    pub(crate) fn new(limit: InputOutputLimit) -> Self {
        Self {
            input_budget: ResourceBudget::new(
                RedactionResource::Input,
                limit.max_input_bytes(),
            ),
            output_budget: ResourceBudget::new(
                RedactionResource::Output,
                limit.max_output_bytes(),
            ),
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
        if self.input_is_precharged() {
            return self.admit_precharged(domain_output_limit);
        }
        if self.output_closed || self.output_budget.remaining() == 0 {
            self.output_closed = true;
            return RedactionAdmission::Exhausted;
        }
        if self.input_closed
            || self.input_budget.try_consume(input_bytes).is_err()
        {
            return self.reject_input(fallback_bytes);
        }
        let max_output_bytes =
            domain_output_limit.min(self.output_budget.remaining());
        self.admitted_output.push(AdmittedOutput {
            max_output_bytes,
            remaining_output_bytes: self.output_budget.remaining(),
            input_provenance: InputProvenance::Precharged,
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
    pub(crate) fn admit_precharged(
        &mut self,
        domain_output_limit: usize,
    ) -> RedactionAdmission {
        if self.output_closed || self.output_budget.remaining() == 0 {
            self.output_closed = true;
            return RedactionAdmission::Exhausted;
        }
        let max_output_bytes =
            domain_output_limit.min(self.output_budget.remaining());
        self.admitted_output.push(AdmittedOutput {
            max_output_bytes,
            remaining_output_bytes: self.output_budget.remaining(),
            input_provenance: InputProvenance::Precharged,
        });
        RedactionAdmission::Render { max_output_bytes }
    }

    /// Admits output for pure domain formatting without covering nested input.
    ///
    /// Adapters entered beneath this frame must perform their own exact input
    /// admission. Their precharged child frames still deduplicate output bytes
    /// when this output-only parent later commits its completed representation.
    pub(crate) fn admit_output_only(
        &mut self,
        domain_output_limit: usize,
    ) -> RedactionAdmission {
        if self.output_closed || self.output_budget.remaining() == 0 {
            self.output_closed = true;
            return RedactionAdmission::Exhausted;
        }
        let max_output_bytes =
            domain_output_limit.min(self.output_budget.remaining());
        self.admitted_output.push(AdmittedOutput {
            max_output_bytes,
            remaining_output_bytes: self.output_budget.remaining(),
            input_provenance: InputProvenance::OutputOnly,
        });
        RedactionAdmission::Render { max_output_bytes }
    }

    /// Returns whether an active parent already reserved nested input.
    #[inline(always)]
    pub(crate) fn input_is_precharged(&self) -> bool {
        self.admitted_output.last().is_some_and(|frame| {
            frame.input_provenance == InputProvenance::Precharged
        })
    }

    /// Returns whether domain or adapter output is currently being completed.
    #[must_use]
    #[inline(always)]
    fn has_active_output(&self) -> bool {
        !self.admitted_output.is_empty()
    }

    /// Commits exact emitted bytes for one previously admitted fragment.
    pub(crate) fn commit_output(
        &mut self,
        bytes: usize,
        completion: FragmentCompletion,
    ) {
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
            FragmentCompletion::Complete
            | FragmentCompletion::DomainTruncated => {}
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
            || (!self.has_active_output()
                && (self.input_closed || self.input_budget.remaining() == 0))
    }
}

#[cfg(test)]
mod tests {
    use super::DiagnosticBudget;
    use crate::policy::InputOutputLimit;
    use crate::runtime::internal::RedactionAdmission;

    #[test]
    fn precharged_admission_reserves_nested_output() {
        let mut budget = DiagnosticBudget::new(InputOutputLimit::default());
        assert!(matches!(
            budget.admit_precharged(8),
            RedactionAdmission::Render {
                max_output_bytes: 8
            }
        ));
    }
}
