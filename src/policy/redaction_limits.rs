// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable execution limits used while rendering redacted output.

use super::DomainRedactionLimits;
use super::InputOutputLimit;
#[cfg(feature = "json")]
use super::JsonDepthLimit;
#[cfg(feature = "http")]
use crate::http::BodyBudget;

/// Immutable limits that bound diagnostic and ordinary redaction work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionLimits {
    /// Maximum source and output bytes for one diagnostic event.
    diagnostic_event: InputOutputLimit,
    /// Maximum source and output bytes for one ordinary operation.
    ordinary_operation: InputOutputLimit,
    /// Maximum cumulative nodes, collection items, and active domain depth.
    domain: DomainRedactionLimits,
    /// Maximum source and output bytes for one HTTP body operation.
    #[cfg(feature = "http")]
    http_body: BodyBudget,
    /// Maximum JSON recursion depth for structured redaction.
    #[cfg(feature = "json")]
    json_depth_limit: JsonDepthLimit,
}

impl RedactionLimits {
    /// Constructs a complete immutable limit snapshot.
    ///
    /// `diagnostic_event` bounds cumulative input and output for one shared
    /// diagnostic session. `ordinary_operation` bounds an independent ordinary
    /// redaction operation. `domain` bounds cumulative domain nodes and
    /// collection items plus active domain-value depth.
    ///
    /// When the `http` feature is enabled, `http_body` supplies the local input
    /// and output bounds for one HTTP body operation. When the `json` feature
    /// is enabled, `json_depth_limit` bounds structured JSON recursion
    /// depth. Each argument has already been validated by its own type;
    /// this constructor preserves those values without additional
    /// validation.
    #[inline]
    #[must_use]
    pub const fn new(
        diagnostic_event: InputOutputLimit,
        ordinary_operation: InputOutputLimit,
        domain: DomainRedactionLimits,
        #[cfg(feature = "http")] http_body: BodyBudget,
        #[cfg(feature = "json")] json_depth_limit: JsonDepthLimit,
    ) -> Self {
        Self {
            diagnostic_event,
            ordinary_operation,
            domain,
            #[cfg(feature = "http")]
            http_body,
            #[cfg(feature = "json")]
            json_depth_limit,
        }
    }

    /// Returns the hard diagnostic input and output limits.
    #[inline(always)]
    #[must_use]
    pub const fn diagnostic_event(&self) -> InputOutputLimit {
        self.diagnostic_event
    }

    /// Returns the hard limits for one ordinary redaction operation.
    #[inline(always)]
    #[must_use]
    pub const fn ordinary_operation(&self) -> InputOutputLimit {
        self.ordinary_operation
    }

    /// Returns the hard domain-structure traversal limits.
    #[inline(always)]
    #[must_use]
    pub const fn domain(&self) -> DomainRedactionLimits {
        self.domain
    }

    /// Returns a copy with the diagnostic-event limit replaced.
    #[inline]
    #[must_use]
    pub(crate) const fn with_diagnostic_event(
        mut self,
        limit: InputOutputLimit,
    ) -> Self {
        self.diagnostic_event = limit;
        self
    }

    /// Returns a copy with the ordinary-operation limit replaced.
    #[inline]
    #[must_use]
    pub(crate) const fn with_ordinary_operation(
        mut self,
        limit: InputOutputLimit,
    ) -> Self {
        self.ordinary_operation = limit;
        self
    }

    /// Returns a copy with the domain-structure limits replaced.
    #[inline]
    #[must_use]
    pub(crate) const fn with_domain(
        mut self,
        limits: DomainRedactionLimits,
    ) -> Self {
        self.domain = limits;
        self
    }

    /// Returns the local hard limits for HTTP body processing.
    #[must_use]
    #[cfg(feature = "http")]
    #[inline(always)]
    pub const fn http_body(&self) -> BodyBudget {
        self.http_body
    }
    /// Returns a copy with the HTTP body limit replaced.
    #[must_use]
    #[cfg(feature = "http")]
    #[inline]
    pub(crate) const fn with_http_body(mut self, limit: BodyBudget) -> Self {
        self.http_body = limit;
        self
    }

    /// Returns the hard recursion-depth limit for structured JSON redaction.
    #[must_use]
    #[cfg(feature = "json")]
    #[inline(always)]
    pub const fn json_depth_limit(&self) -> JsonDepthLimit {
        self.json_depth_limit
    }

    /// Returns a copy with the JSON depth limit replaced.
    #[cfg(feature = "json")]
    #[inline]
    #[must_use]
    pub(crate) const fn with_json_depth_limit(
        mut self,
        budget: JsonDepthLimit,
    ) -> Self {
        self.json_depth_limit = budget;
        self
    }
}

impl Default for RedactionLimits {
    /// Creates limits using the standard input and output defaults.
    #[inline]

    fn default() -> Self {
        Self {
            diagnostic_event: InputOutputLimit::default(),
            ordinary_operation: InputOutputLimit::default(),
            domain: DomainRedactionLimits::default(),
            #[cfg(feature = "http")]
            http_body: BodyBudget::default(),
            #[cfg(feature = "json")]
            json_depth_limit: JsonDepthLimit::default(),
        }
    }
}
