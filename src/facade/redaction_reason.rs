// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Reasons why a safe representation is degraded.

/// Reason why a policy-transformed representation is degraded.
///
/// # Examples
///
/// ```
/// use qubit_redact::{RedactionPolicy, RedactionReason, Redactor};
///
/// let policy = RedactionPolicy::builder().limits(|limits| {
///     limits.max_input_bytes(0);
/// })?.build()?;
/// let output = Redactor::new(policy).redact_field("id", "42");
/// assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
/// # Ok::<(), qubit_redact::PolicyError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RedactionReason {
    /// Input admission rejected bytes beyond the configured input allowance.
    InputLimitReached,
    /// The shared transaction output reached its configured byte limit.
    OutputLimitReached,
    /// Structural traversal reached a configured limit.
    TraversalLimitReached,
    /// Maximum traversal depth was reached.
    DepthLimitReached,
    /// Source data was already truncated at its ingress boundary.
    SourceTruncated,
    /// Source data was not valid JSON.
    InvalidJson,
    /// Source data was not a valid URI.
    InvalidUri,
    /// Source content type was invalid.
    InvalidContentType,
    /// Source content type is unsupported.
    UnsupportedContentType,
    /// Source data was not a valid URL-encoded form.
    InvalidForm,
    /// Source data was not a valid multipart body.
    InvalidMultipart,
    /// A display formatter failed before producing a complete scalar value.
    FormattingFailed,
}

impl RedactionReason {
    /// Returns the stable bit assigned to this reason in a reason set.
    ///
    /// # Returns
    ///
    /// Exactly one bit identifying this reason in the internal reason set.
    #[must_use]
    pub(super) const fn bit(self) -> u64 {
        match self {
            Self::InputLimitReached => 1 << 0,
            Self::OutputLimitReached => 1 << 1,
            Self::TraversalLimitReached => 1 << 2,
            Self::DepthLimitReached => 1 << 3,
            Self::SourceTruncated => 1 << 4,
            Self::InvalidJson => 1 << 5,
            Self::InvalidUri => 1 << 6,
            Self::InvalidContentType => 1 << 7,
            Self::UnsupportedContentType => 1 << 8,
            Self::InvalidForm => 1 << 9,
            Self::InvalidMultipart => 1 << 10,
            Self::FormattingFailed => 1 << 11,
        }
    }
}
