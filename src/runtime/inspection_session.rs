// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-rendering transaction with typed inspection ownership.

use std::sync::Arc;

use super::inspection_runtime::InspectionRuntime;
use super::runtime_core::RuntimeCore;
use super::runtime_session::RuntimeSession;
use crate::Redact;
use crate::RedactionCompletion;
use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionInspectionResult;
use crate::RedactionPolicy;
use crate::RedactionReasons;
use crate::Sensitivity;

/// Owns one non-rendering runtime and its sensitivity accumulator.
pub(crate) struct InspectionSession {
    /// Shared accounting and obligatory inspection accumulator.
    runtime: InspectionRuntime,
}

impl InspectionSession {
    /// Creates an inspection transaction from one policy snapshot.
    #[must_use]
    pub(crate) fn new(policy: Arc<RedactionPolicy>) -> Self {
        Self {
            runtime: InspectionRuntime::new(policy),
        }
    }

    /// Classifies one domain value without rendering field content.
    pub(crate) fn inspect<T>(&mut self, value: &T)
    where
        T: Redact + ?Sized,
    {
        let mut writer = crate::domain::RedactionWriter::new_root(self);
        value.write_redacted(&mut writer);
        let _ = writer.finish_with_completion();
    }

    /// Consumes this transaction into a conclusive result or fail-closed error.
    pub(crate) fn finish(self) -> RedactionInspectionResult {
        let (max_sensitivity, summary) = self.runtime.into_parts();
        if summary.completion() == RedactionCompletion::Complete
            && summary.reasons() == RedactionReasons::empty()
        {
            return Ok(RedactionInspection::new(
                summary.is_redaction_disabled(),
                max_sensitivity,
                summary.usage(),
            ));
        }
        Err(RedactionInspectionError::new(
            summary.reasons(),
            summary.usage(),
        ))
    }
}

impl RuntimeSession for InspectionSession {
    /// Borrows the publication-independent inspection core.
    #[inline(always)]
    fn runtime(&self) -> &RuntimeCore {
        &self.runtime.core
    }

    /// Mutably borrows the publication-independent inspection core.
    #[inline(always)]
    fn runtime_mut(&mut self) -> &mut RuntimeCore {
        &mut self.runtime.core
    }

    /// Identifies this session as non-rendering inspection state.
    #[inline(always)]
    fn is_inspection(&self) -> bool {
        true
    }

    /// Records the strongest sensitivity in the obligatory accumulator.
    #[inline(always)]
    fn observe_sensitivity(&mut self, sensitivity: Sensitivity) {
        self.runtime.observe_sensitivity(sensitivity);
    }
}
