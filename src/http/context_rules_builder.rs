// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Construction state for one HTTP field-policy context.

use crate::{
    policy::RedactionRulesBuilder, PolicyError, PolicyLocation, RedactionFloor,
    RedactionFloorState, RedactionRules,
};

/// Construction state for a single HTTP field context.
#[derive(Debug, Clone)]
pub(super) struct ContextRulesBuilder {
    pub(super) rules: RedactionRulesBuilder,
    pub(super) floor: Option<RedactionFloor>,
    pub(super) floor_state: RedactionFloorState,
}

impl ContextRulesBuilder {
    /// Creates empty application rules inheriting `floor`.
    pub(super) fn empty(location: PolicyLocation, floor: RedactionFloor) -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(location),
            floor: Some(floor),
            floor_state: RedactionFloorState::Explicit,
        }
    }

    /// Copies an immutable rules snapshot while assigning validation location.
    pub(super) fn from_rules(rules: &RedactionRules, location: PolicyLocation) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(&rules.clone_application(), location),
            floor: rules.floor().cloned(),
            floor_state: rules.floor_state(),
        }
    }

    /// Replaces the floor snapshot.
    pub(super) fn with_floor(mut self, floor: RedactionFloor) -> Self {
        self.floor = Some(floor);
        self.floor_state = RedactionFloorState::Explicit;
        self
    }

    /// Disables the floor snapshot.
    pub(super) fn disable_floor(mut self) -> Self {
        self.floor = None;
        self.floor_state = RedactionFloorState::Disabled;
        self
    }

    /// Builds the immutable rules snapshot.
    pub(super) fn build(self) -> Result<RedactionRules, PolicyError> {
        Ok(RedactionRules::new(
            self.rules.build_inner()?,
            self.floor,
            self.floor_state,
        ))
    }
}
