// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Transactional view over URI visibility settings.

/// Mutable view over URI-specific behavior.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::formats::uri::UriPathPolicy;
///
/// let policy = RedactionPolicy::builder().uri(|uri| {
///     uri.path(UriPathPolicy::Redact);
/// })?.build()?;
/// assert!(!policy.is_disabled());
/// # Ok::<(), qubit_redact::PolicyError>(())
/// ```
#[cfg(feature = "uri")]
pub struct UriPolicyBuilderView<'a> {
    /// URI builder receiving view changes.
    pub(super) builder: &'a mut crate::formats::uri::UriPolicyBuilder,
}

#[cfg(feature = "uri")]
impl UriPolicyBuilderView<'_> {
    /// Selects whether URI paths remain visible or are replaced by a marker.
    ///
    /// # Parameters
    ///
    /// * `policy` — the path visibility behavior applied when the policy is
    ///   used to redact a URI.
    ///
    /// # Returns
    ///
    /// A mutable reference to this view, allowing additional URI settings to
    /// be configured in the same closure.
    #[inline(always)]
    pub fn path(&mut self, policy: crate::formats::uri::UriPathPolicy) -> &mut Self {
        self.builder.path_policy(policy);
        self
    }

    /// Selects whether URI fragments remain visible or are masked.
    ///
    /// # Parameters
    ///
    /// * `policy` — the fragment visibility behavior applied when the policy is
    ///   used to redact a URI.
    ///
    /// # Returns
    ///
    /// A mutable reference to this view, allowing additional URI settings to
    /// be configured in the same closure.
    #[inline(always)]
    pub fn fragment(&mut self, policy: crate::formats::uri::UriFragmentPolicy) -> &mut Self {
        self.builder.fragment_policy(policy);
        self
    }
}
