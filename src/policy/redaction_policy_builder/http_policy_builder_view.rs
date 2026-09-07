// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Transactional view over HTTP policy contexts.

use super::HttpContextBuilderView;
use super::PolicyError;
use super::RedactionFloor;
use super::RedactionPolicyBuilder;

/// Mutable view over all HTTP context differences.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::formats::http::UrlPathPolicy;
///
/// let policy = RedactionPolicy::builder().http(|http| {
///     http.url_path(UrlPathPolicy::Redact);
/// })?.build()?;
/// assert!(!policy.is_disabled());
/// # Ok::<(), qubit_redact::PolicyError>(())
/// ```
#[cfg(feature = "http")]
pub struct HttpPolicyBuilderView<'a> {
    /// Root builder receiving HTTP policy changes.
    pub(super) builder: &'a mut RedactionPolicyBuilder,
    /// First validation error recorded by the transactional view.
    pub(super) error: Option<PolicyError>,
}

#[cfg(feature = "http")]
impl HttpPolicyBuilderView<'_> {
    /// Returns the header context view.
    #[must_use]
    #[inline(always)]
    pub fn header(&mut self) -> HttpContextBuilderView<'_> {
        HttpContextBuilderView {
            builder: &mut self.builder.http,
            error: &mut self.error,
            context: crate::formats::http::HttpFieldContext::Header,
        }
    }

    /// Returns the query/form context view.
    #[must_use]
    #[inline(always)]
    pub fn query(&mut self) -> HttpContextBuilderView<'_> {
        HttpContextBuilderView {
            builder: &mut self.builder.http,
            error: &mut self.error,
            context: crate::formats::http::HttpFieldContext::Query,
        }
    }

    /// Returns the structured-body context view.
    #[must_use]
    #[inline(always)]
    pub fn body(&mut self) -> HttpContextBuilderView<'_> {
        HttpContextBuilderView {
            builder: &mut self.builder.http,
            error: &mut self.error,
            context: crate::formats::http::HttpFieldContext::Body,
        }
    }

    /// Sets URL path visibility for HTTP diagnostics.
    #[inline(always)]
    pub fn url_path(&mut self, policy: crate::formats::http::UrlPathPolicy) -> &mut Self {
        self.builder.http.url_path_mut(policy);
        self
    }

    /// Sets opaque text-body visibility for HTTP diagnostics.
    #[inline(always)]
    pub fn text_body(&mut self, policy: crate::formats::http::TextBodyPolicy) -> &mut Self {
        self.builder.http.text_body_mut(policy);
        self
    }

    /// Sets the same floor for every HTTP field context.
    #[inline(always)]
    pub fn floor_all(&mut self, floor: RedactionFloor) -> &mut Self {
        self.builder.http.floor_all_mut(floor);
        self
    }

    /// Disables every HTTP field-context floor explicitly.
    #[inline(always)]
    pub fn disable_all_floors(&mut self) -> &mut Self {
        self.builder.http.disable_all_floors_mut();
        self
    }

    /// Sets the handling of root and array JSON scalar values in HTTP
    /// bodies.
    #[inline(always)]
    pub fn unkeyed_json(&mut self, policy: crate::UnkeyedJsonValuePolicy) -> &mut Self {
        self.builder.unkeyed_json_value_policy = policy;
        self
    }
}
