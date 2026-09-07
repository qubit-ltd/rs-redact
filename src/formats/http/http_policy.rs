// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable policy snapshot for every HTTP redaction context.

use std::sync::Arc;

use super::TextBodyPolicy;
use super::UrlPathPolicy;
use super::internal::HttpPolicyParts;
use crate::RedactionRules;

/// Combines HTTP field rules and rendering choices.
///
/// Resource limits belong to the enclosing [`crate::RedactionPolicy`].
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::formats::http::UrlPathPolicy;
///
/// let policy = RedactionPolicy::standard();
/// assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Preserve);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPolicy {
    /// Shared immutable context policies behind cheap policy clones.
    inner: Arc<HttpPolicyParts>,
}

impl HttpPolicy {
    /// Creates an HTTP policy from its validated component policies.
    ///
    /// # Parameters
    ///
    /// * `parts` - Validated context rules and rendering choices to own.
    ///
    /// # Returns
    ///
    /// An immutable snapshot whose clones share the same Arc payload.
    #[must_use]
    #[inline(always)]
    pub(super) fn from_parts(parts: HttpPolicyParts) -> Self {
        Self { inner: Arc::new(parts) }
    }

    /// Returns the header field-rule snapshot.
    ///
    /// # Returns
    ///
    /// Borrowed classification rules for HTTP header names.
    #[must_use]
    #[inline(always)]
    pub fn header_rules(&self) -> &RedactionRules {
        &self.inner.header_rules
    }

    /// Returns the query and form field-rule snapshot.
    ///
    /// # Returns
    ///
    /// Borrowed classification rules shared by query and form fields.
    #[must_use]
    #[inline(always)]
    pub fn query_rules(&self) -> &RedactionRules {
        &self.inner.query_rules
    }

    /// Returns the structured-body field-rule snapshot.
    ///
    /// # Returns
    ///
    /// Borrowed classification rules for structured body fields.
    #[must_use]
    #[inline(always)]
    pub fn body_rules(&self) -> &RedactionRules {
        &self.inner.body_rules
    }

    /// Returns the URL path visibility choice.
    ///
    /// # Returns
    ///
    /// The immutable URL-path visibility policy.
    #[must_use]
    #[inline(always)]
    pub fn url_path_policy(&self) -> UrlPathPolicy {
        self.inner.url_path_policy
    }

    /// Returns the opaque text-body visibility choice.
    ///
    /// # Returns
    ///
    /// The immutable visibility policy for opaque text bodies.
    #[must_use]
    #[inline(always)]
    pub fn text_body_policy(&self) -> TextBodyPolicy {
        self.inner.text_body_policy
    }
}
