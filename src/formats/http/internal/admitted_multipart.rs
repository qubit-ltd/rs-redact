// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Multipart admission state indexed by source segment.

use super::AdmittedMultipartBody;

/// Parsed multipart bodies retained between admission and rendering.
pub(in crate::formats::http) struct AdmittedMultipart {
    /// Structured values indexed by multipart segment position.
    pub(in crate::formats::http) parts: Vec<Option<AdmittedMultipartBody>>,
}
