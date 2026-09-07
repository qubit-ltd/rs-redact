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
    /// Sets URI path visibility.
    #[inline(always)]
    pub fn path(&mut self, policy: crate::formats::uri::UriPathPolicy) -> &mut Self {
        self.builder.path_policy_mut(policy);
        self
    }

    /// Sets URI fragment visibility.
    #[inline(always)]
    pub fn fragment(&mut self, policy: crate::formats::uri::UriFragmentPolicy) -> &mut Self {
        self.builder.fragment_policy_mut(policy);
        self
    }
}
