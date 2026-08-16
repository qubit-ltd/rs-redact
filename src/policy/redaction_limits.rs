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
use crate::formats::http::BodyBudget;

/// Mutable construction state for [`RedactionLimits`].
#[derive(Debug, Clone, Copy)]
pub struct RedactionLimitsBuilder {
    diagnostic_event: InputOutputLimit,
    ordinary_operation: InputOutputLimit,
    domain: DomainRedactionLimits,
    #[cfg(feature = "http")]
    http_body: BodyBudget,
    #[cfg(feature = "json")]
    json_depth_limit: JsonDepthLimit,
}

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
    /// Creates a builder initialized with the standard execution limits.
    #[must_use]
    #[inline]
    pub fn builder() -> RedactionLimitsBuilder {
        RedactionLimitsBuilder::default()
    }

    /// Creates a builder by copying an existing limit snapshot.
    #[must_use]
    #[inline]
    pub(crate) fn builder_from(base: &Self) -> RedactionLimitsBuilder {
        RedactionLimitsBuilder {
            diagnostic_event: base.diagnostic_event,
            ordinary_operation: base.ordinary_operation,
            domain: base.domain,
            #[cfg(feature = "http")]
            http_body: base.http_body,
            #[cfg(feature = "json")]
            json_depth_limit: base.json_depth_limit,
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

    /// Returns the local hard limits for HTTP body processing.
    #[must_use]
    #[cfg(feature = "http")]
    #[inline(always)]
    pub const fn http_body(&self) -> BodyBudget {
        self.http_body
    }
    /// Returns the hard recursion-depth limit for structured JSON redaction.
    #[must_use]
    #[cfg(feature = "json")]
    #[inline(always)]
    pub const fn json_depth_limit(&self) -> JsonDepthLimit {
        self.json_depth_limit
    }
}

impl RedactionLimitsBuilder {
    /// Sets the diagnostic-event limit.
    #[inline]
    pub fn diagnostic_event(&mut self, limit: InputOutputLimit) -> &mut Self {
        self.diagnostic_event = limit;
        self
    }

    /// Sets the ordinary-operation limit.
    #[inline]
    pub fn ordinary_operation(&mut self, limit: InputOutputLimit) -> &mut Self {
        self.ordinary_operation = limit;
        self
    }

    /// Sets the domain traversal limits.
    #[inline]
    pub fn domain(&mut self, limits: DomainRedactionLimits) -> &mut Self {
        self.domain = limits;
        self
    }

    /// Sets the HTTP body limit.
    #[cfg(feature = "http")]
    #[inline]
    pub fn http_body(&mut self, limit: BodyBudget) -> &mut Self {
        self.http_body = limit;
        self
    }

    /// Sets the JSON depth limit.
    #[cfg(feature = "json")]
    #[inline]
    pub fn json_depth_limit(&mut self, limit: JsonDepthLimit) -> &mut Self {
        self.json_depth_limit = limit;
        self
    }

    /// Builds the immutable execution limits.
    #[must_use]
    #[inline]
    pub fn build(self) -> RedactionLimits {
        RedactionLimits {
            diagnostic_event: self.diagnostic_event,
            ordinary_operation: self.ordinary_operation,
            domain: self.domain,
            #[cfg(feature = "http")]
            http_body: self.http_body,
            #[cfg(feature = "json")]
            json_depth_limit: self.json_depth_limit,
        }
    }
}

impl Default for RedactionLimitsBuilder {
    /// Creates a builder with standard execution limits.
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

impl Default for RedactionLimits {
    /// Creates limits using the standard input and output defaults.
    #[inline]

    fn default() -> Self {
        Self::builder().build()
    }
}
