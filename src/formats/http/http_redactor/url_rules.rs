// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URL redaction limits.

/// Maximum number of recursively embedded HTTP URLs to redact.
pub(in crate::formats::http) const MAX_NESTED_URL_DEPTH: usize = 8;
