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
    #[inline(always)]
    fn runtime(&self) -> &RuntimeCore {
        &self.core
    }

    /// Mutably borrows the publication-independent rendering core.
    #[inline(always)]
    fn runtime_mut(&mut self) -> &mut RuntimeCore {
        &mut self.core
    }

    /// Identifies this runtime as rendering state.
    #[inline(always)]
    fn is_inspection(&self) -> bool {
        false
    }

    /// Ignores inspection-only observations in rendering mode.
    #[inline(always)]
    fn observe_sensitivity(&mut self, _sensitivity: Sensitivity) {
        // Rendering resolves sensitivities into output instead of accumulating
        // them for a separate inspection result.
    }
}

impl RenderRuntime {
    /// Creates rendering state governed by one immutable policy snapshot.
    #[must_use]
    pub(super) fn new(policy: Arc<RedactionPolicy>) -> Self {
        Self {
            core: RuntimeCore::new(policy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RenderRuntime;
    use crate::RedactionPolicy;
    use crate::Sensitivity;
    use crate::runtime::runtime_session::RuntimeSession;

    /// Rendering runtime exposes both core access paths and ignores inspection
    /// observations.
    #[test]
    fn rendering_runtime_implements_its_typed_mode_contract() {
        let mut runtime = RenderRuntime::new(RedactionPolicy::standard().into());

        assert!(!RuntimeSession::is_inspection(&runtime));
        RuntimeSession::observe_sensitivity(&mut runtime, Sensitivity::Secret);
        let _ = RuntimeSession::runtime(&runtime);
        let _ = RuntimeSession::runtime_mut(&mut runtime);
    }
}
