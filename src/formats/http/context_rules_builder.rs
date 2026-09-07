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
    /// Mutable application rules for this HTTP field namespace.
    pub(super) rules: RedactionRulesBuilder,
    /// Optional minimum floor applied after application rules.
    pub(super) floor: Option<RedactionFloor>,
}

impl ContextRulesBuilder {
    /// Creates empty context overrides.
    ///
    /// # Parameters
    ///
    /// - `location`: HTTP context attached to subsequent validation errors.
    ///
    /// # Returns
    ///
    /// An empty application rule builder with no minimum floor.
    #[must_use]
    #[inline]
    pub(super) fn empty(location: PolicyLocation) -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(location),
            floor: None,
        }
    }

    /// Copies an immutable rules snapshot while assigning validation location.
    ///
    /// # Parameters
    ///
    /// - `rules`: Immutable application rules and optional floor to copy.
    /// - `location`: HTTP context attached to subsequent validation errors.
    ///
    /// # Returns
    ///
    /// An independent mutable builder initialized from the supplied snapshot.
    #[must_use]
    #[inline]
    pub(super) fn from_rules(rules: &RedactionRules, location: PolicyLocation) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(&rules.clone_application(), location),
            floor: rules.floor().cloned(),
        }
    }

    /// Replaces the floor snapshot.
    ///
    /// # Parameters
    ///
    /// - `floor`: Immutable minimum protection floor to install.
    #[inline]
    pub(super) fn with_floor(&mut self, floor: RedactionFloor) {
        self.floor = Some(floor);
    }

    /// Disables the floor snapshot.
    #[inline(always)]
    pub(super) fn disable_floor(&mut self) {
        self.floor = None;
    }

    /// Builds the immutable rules snapshot.
    ///
    /// # Returns
    ///
    /// The application rules and optional floor as one immutable snapshot.
    ///
    /// # Errors
    ///
    /// Currently always succeeds because individual rule setters validate
    /// their inputs before storing them.
    #[inline]
    pub(super) fn build(self) -> Result<RedactionRules, PolicyError> {
        Ok(RedactionRules::new(self.rules.build_inner()?, self.floor))
    }
}
