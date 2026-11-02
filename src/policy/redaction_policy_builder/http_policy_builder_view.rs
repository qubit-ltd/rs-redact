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

    /// Sets how unkeyed JSON scalar values are handled across JSON and HTTP
    /// bodies.
    ///
    /// This root-level setting applies to scalar JSON roots and scalar array
    /// elements in both ordinary JSON APIs and HTTP JSON, NDJSON, and multipart
    /// JSON parts. Object properties continue to use their field rules.
    ///
    /// The same setting can be configured directly with
    /// [`RedactionPolicyBuilder::unkeyed_json_value_policy`].
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

#[cfg(all(test, feature = "http", feature = "uri", feature = "json"))]
mod tests {
    use crate::RedactionFloor;
    use crate::RedactionPolicy;
    use crate::Sensitivity;
    use crate::UnkeyedJsonValuePolicy;
    use crate::formats::http::TextBodyPolicy;
    use crate::formats::http::UrlPathPolicy;
    use crate::formats::uri::UriFragmentPolicy;
    use crate::formats::uri::UriPathPolicy;

    #[test]
    fn test_grouped_views_exercise_settings_in_the_library_test_target() {
        let floor = RedactionFloor::builder()
            .raise("credential", Sensitivity::High)
            .expect("floor field name should be valid")
            .build()
            .expect("floor should be valid");
        let policy = RedactionPolicy::builder()
            .http(|http| {
                http.header()
                    .raise("x-api-key", Sensitivity::Secret)
                    .expect("header field name should be valid");
                http.query()
                    .raise("access_token", Sensitivity::High)
                    .expect("query field name should be valid");
                http.body()
                    .raise("session", Sensitivity::Medium)
                    .expect("body field name should be valid");
                http.url_path(UrlPathPolicy::Redact)
                    .text_body(TextBodyPolicy::PassThrough)
                    .floor_all(floor)
                    .disable_all_floors()
                    .unkeyed_json(UnkeyedJsonValuePolicy::Redact);
            })
            .expect("HTTP settings should be valid")
            .uri(|uri| {
                uri.path(UriPathPolicy::Redact)
                    .fragment(UriFragmentPolicy::Preserve);
            })
            .expect("URI settings should be valid")
            .build()
            .expect("policy should be valid");

        assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Redact);
        assert_eq!(
            policy.http().text_body_policy(),
            TextBodyPolicy::PassThrough
        );
        assert_eq!(
            policy.http().header_rules().sensitivity_for("x-api-key"),
            Some(Sensitivity::Secret)
        );
        assert_eq!(
            policy.http().query_rules().sensitivity_for("access_token"),
            Some(Sensitivity::High)
        );
        assert_eq!(
            policy.http().body_rules().sensitivity_for("session"),
            Some(Sensitivity::Medium)
        );
        assert!(policy.http().header_rules().floor().is_none());
        assert!(policy.http().query_rules().floor().is_none());
        assert!(policy.http().body_rules().floor().is_none());
        assert_eq!(
            policy.unkeyed_json_value_policy(),
            UnkeyedJsonValuePolicy::Redact
        );
        assert_eq!(policy.uri().path_policy(), UriPathPolicy::Redact);
        assert_eq!(policy.uri().fragment_policy(), UriFragmentPolicy::Preserve);
    }
}
