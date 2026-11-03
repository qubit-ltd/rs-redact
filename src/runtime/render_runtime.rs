// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Rendering runtime backed by shared transaction accounting.

use std::sync::Arc;

use super::runtime_core::RuntimeCore;
use super::runtime_session::RuntimeSession;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Owns shared accounting for a transaction that produces text.
pub(super) struct RenderRuntime {
    /// Policy, budget, summary, and structural state shared by renderers.
    pub(super) core: RuntimeCore,
}

impl RuntimeSession for RenderRuntime {
    /// Borrows the publication-independent rendering core.
    ///
    /// # Returns
    ///
    /// The accounting core borrowed without changing transaction state.
    #[inline(always)]
    fn runtime(&self) -> &RuntimeCore {
        &self.core
    }

    /// Mutably borrows the publication-independent rendering core.
    ///
    /// # Returns
    ///
    /// An exclusive borrow of the transaction accounting core.
    #[inline(always)]
    fn runtime_mut(&mut self) -> &mut RuntimeCore {
        &mut self.core
    }

    /// Identifies this runtime as rendering state.
    ///
    /// # Returns
    ///
    /// Whether this implementation observes sensitivity without rendering
    /// output.
    #[inline(always)]
    fn is_inspection(&self) -> bool {
        false
    }

    /// Ignores inspection-only observations in rendering mode.
    ///
    /// # Parameters
    ///
    /// - `_sensitivity`: Classification ignored by this rendering mode.
    #[inline(always)]
    fn observe_sensitivity(&mut self, _sensitivity: Sensitivity) {
        // Rendering resolves sensitivities into output instead of accumulating
        // them for a separate inspection result.
    }
}

impl RenderRuntime {
    /// Creates rendering state governed by one immutable policy snapshot.
    ///
    /// # Parameters
    ///
    /// - `policy`: Immutable snapshot shared by the new transaction.
    ///
    /// # Returns
    ///
    /// Fresh mode-specific state with empty resource accounting.
    #[must_use]
    #[inline(always)]
    pub(super) fn new(policy: Arc<RedactionPolicy>) -> Self {
        Self {
            core: RuntimeCore::new(policy),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::RenderRuntime;
    use crate::RedactionPolicy;
    use crate::Sensitivity;
    use crate::runtime::runtime_session::RuntimeSession;

    /// Covers the concrete render adapter's mode-specific trait implementation.
    #[test]
    fn test_render_runtime_exposes_its_core_and_ignores_observations() {
        let mut runtime = RenderRuntime::new(Arc::new(RedactionPolicy::standard()));

        assert!(!runtime.is_inspection());
        runtime.observe_sensitivity(Sensitivity::Secret);
        let core = runtime.runtime() as *const _;
        assert!(std::ptr::eq(core, runtime.runtime_mut()));
    }
}
