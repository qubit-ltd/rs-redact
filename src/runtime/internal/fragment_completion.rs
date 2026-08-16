// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Completion state for one admitted redaction fragment.

/// Describes how an admitted fragment finished rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FragmentCompletion {
    /// The fragment rendered completely.
    Complete,
    /// A domain-specific ceiling truncated the fragment without exhausting the
    /// shared session.
    DomainTruncated,
    /// The shared session ceiling truncated the fragment and is now closed.
    SessionTruncated,
}
