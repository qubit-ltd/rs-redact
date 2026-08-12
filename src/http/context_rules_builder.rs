// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
// qubit-style: allow source-test-pair
//! Construction state for one HTTP field-policy context.

use crate::PolicyError;
use crate::PolicyLocation;
use crate::RedactionFloor;
use crate::RedactionRules;
use crate::policy::RedactionRulesBuilder;

/// Construction state for a single HTTP field context.
#[derive(Debug, Clone)]
pub(super) struct ContextRulesBuilder {
    pub(super) rules: RedactionRulesBuilder,
    pub(super) floor: Option<RedactionFloor>,
}

impl ContextRulesBuilder {
    /// Creates empty context overrides.
    pub(super) fn empty(location: PolicyLocation) -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(location),
            floor: None,
        }
    }

    /// Copies an immutable rules snapshot while assigning validation location.
    pub(super) fn from_rules(
        rules: &RedactionRules,
        location: PolicyLocation,
    ) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(
                &rules.clone_application(),
                location,
            ),
            floor: rules.floor().cloned(),
        }
    }

    /// Replaces the floor snapshot.
    pub(super) fn with_floor(&mut self, floor: RedactionFloor) {
        self.floor = Some(floor);
    }

    /// Disables the floor snapshot.
    pub(super) fn disable_floor(&mut self) {
        self.floor = None;
    }

    /// Builds the immutable rules snapshot.
    pub(super) fn build(self) -> Result<RedactionRules, PolicyError> {
        Ok(RedactionRules::new(self.rules.build_inner()?, self.floor))
    }
}
