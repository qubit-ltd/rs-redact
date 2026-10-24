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
use crate::UnkeyedJsonValuePolicy;
use crate::formats::http::HttpFieldContext;
use crate::formats::http::TextBodyPolicy;
use crate::formats::http::UrlPathPolicy;

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
            context: HttpFieldContext::Header,
        }
    }

    /// Returns the URL query context view.
    ///
    /// Form fields in `application/x-www-form-urlencoded` bodies use
    /// [`Self::body`] instead.
    #[must_use]
    #[inline(always)]
    pub fn query(&mut self) -> HttpContextBuilderView<'_> {
        HttpContextBuilderView {
            builder: &mut self.builder.http,
            error: &mut self.error,
            context: HttpFieldContext::Query,
        }
    }

    /// Returns the structured-body context view.
    #[must_use]
    #[inline(always)]
    pub fn body(&mut self) -> HttpContextBuilderView<'_> {
        HttpContextBuilderView {
            builder: &mut self.builder.http,
            error: &mut self.error,
            context: HttpFieldContext::Body,
        }
    }

    /// Sets whether URL paths are preserved or redacted in HTTP diagnostics.
    ///
    /// # Parameters
    ///
    /// * `policy` — the visibility policy applied to every HTTP URL path.
    ///
    /// # Returns
    ///
    /// A mutable reference to this view for further configuration.
    #[inline(always)]
    pub fn url_path(&mut self, policy: UrlPathPolicy) -> &mut Self {
        self.builder.http.url_path_mut(policy);
        self
    }

    /// Sets whether opaque text bodies are preserved or redacted in HTTP
    /// diagnostics.
    ///
    /// # Parameters
    ///
    /// * `policy` — the visibility policy applied to opaque text bodies.
    ///
    /// # Returns
    ///
    /// A mutable reference to this view for further configuration.
    #[inline(always)]
    pub fn text_body(&mut self, policy: TextBodyPolicy) -> &mut Self {
        self.builder.http.text_body_mut(policy);
        self
    }

    /// Sets the same minimum-protection floor for headers, URL query fields,
    /// and structured-body fields.
    ///
    /// # Parameters
    ///
    /// * `floor` — the floor applied to all HTTP field contexts.
    ///
    /// # Returns
    ///
    /// A mutable reference to this view for further configuration.
    #[inline(always)]
    pub fn floor_all(&mut self, floor: RedactionFloor) -> &mut Self {
        self.builder.http.floor_all_mut(floor);
        self
    }

    /// Removes explicit floors from the header, URL query, and structured-body
    /// contexts.
    ///
    /// # Returns
    ///
    /// A mutable reference to this view for further configuration.
    #[inline(always)]
    pub fn disable_all_floors(&mut self) -> &mut Self {
        self.builder.http.disable_all_floors_mut();
        self
    }

    /// Sets how root and array JSON scalar values in HTTP bodies are handled.
    /// This setting does not change handling of keyed object fields.
    ///
    /// # Parameters
    ///
    /// * `policy` — the handling policy for JSON values without a field key.
    ///
    /// # Returns
    ///
    /// A mutable reference to this view for further configuration.
    #[inline(always)]
    pub fn unkeyed_json(&mut self, policy: UnkeyedJsonValuePolicy) -> &mut Self {
        self.builder.unkeyed_json_value_policy = policy;
        self
    }
}
