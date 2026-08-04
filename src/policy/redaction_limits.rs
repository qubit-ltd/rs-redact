// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable execution limits used while rendering redacted output.

#[cfg(feature = "json")]
use super::JsonDepthBudget;

use super::InputOutputLimit;

#[cfg(feature = "http")]
use crate::http::BodyBudget;

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionLimits {
    /// Maximum source and output bytes for one diagnostic event.
    diagnostic_event: InputOutputLimit,
    /// Maximum source and output bytes for one ordinary operation.
    ordinary_operation: InputOutputLimit,
    /// Maximum source and output bytes for one HTTP body operation.
    #[cfg(feature = "http")]
    http_body: BodyBudget,
    /// Maximum JSON recursion depth for structured redaction.
    #[cfg(feature = "json")]
    json_depth_budget: JsonDepthBudget,
}

impl RedactionLimits {
    /// Constructs limits from a validated diagnostic and optional JSON depth
    /// limit.
    #[inline]
    pub const fn new(
        diagnostic_event: InputOutputLimit,
        ordinary_operation: InputOutputLimit,
        #[cfg(feature = "http")] http_body: BodyBudget,
        #[cfg(feature = "json")] json_depth_budget: JsonDepthBudget,
    ) -> Self {
        Self {
            diagnostic_event,
            ordinary_operation,
            #[cfg(feature = "http")]
            http_body,
            #[cfg(feature = "json")]
            json_depth_budget,
        }
    }

    /// Returns the hard diagnostic input and output limits.
    #[inline(always)]
    pub const fn diagnostic_event(&self) -> InputOutputLimit {
        self.diagnostic_event
    }

    /// Returns the hard limits for one ordinary redaction operation.
    #[inline(always)]
    pub const fn ordinary_operation(&self) -> InputOutputLimit {
        self.ordinary_operation
    }

    /// Returns a copy with the diagnostic-event limit replaced.
    #[inline]
    pub(crate) const fn with_diagnostic_event(
        mut self,
        limit: InputOutputLimit,
    ) -> Self {
        self.diagnostic_event = limit;
        self
    }

    /// Returns a copy with the ordinary-operation limit replaced.
    #[inline]
    pub(crate) const fn with_ordinary_operation(
        mut self,
        limit: InputOutputLimit,
    ) -> Self {
        self.ordinary_operation = limit;
        self
    }
    /// Returns the local hard limits for HTTP body processing.
    #[cfg(feature = "http")]
    #[inline(always)]
    pub const fn http_body(&self) -> BodyBudget {
        self.http_body
    }
    /// Returns a copy with the HTTP body limit replaced.
    #[cfg(feature = "http")]
    #[inline]
    pub(crate) const fn with_http_body(mut self, limit: BodyBudget) -> Self {
        self.http_body = limit;
        self
    }

    /// Returns the hard recursion-depth limit for structured JSON redaction.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub const fn json_depth_budget(&self) -> JsonDepthBudget {
        self.json_depth_budget
    }

    /// Returns a copy with the JSON depth limit replaced.
    #[cfg(feature = "json")]
    #[inline]
    pub(crate) const fn with_json_depth_budget(
        mut self,
        budget: JsonDepthBudget,
    ) -> Self {
        self.json_depth_budget = budget;
        self
    }
}

impl Default for RedactionLimits {
    #[inline]
    fn default() -> Self {
        Self {
            diagnostic_event: InputOutputLimit::default(),
            ordinary_operation: InputOutputLimit::default(),
            #[cfg(feature = "http")]
            http_body: BodyBudget::default(),
            #[cfg(feature = "json")]
            json_depth_budget: JsonDepthBudget::default(),
        }
    }
}
