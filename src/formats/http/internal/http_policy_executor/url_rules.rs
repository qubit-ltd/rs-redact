// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URL redaction limits.

use url::Url;

use crate::formats::http::UrlPathPolicy;

/// Maximum number of recursively embedded HTTP URLs to redact.
pub(in crate::formats::http) const MAX_NESTED_URL_DEPTH: usize = 8;

/// Returns whether the configured policy redacts this URL's path.
///
/// Opaque URLs have no hierarchical root path, so any non-empty opaque path
/// is redactable. Hierarchical URLs preserve their root `/` path.
pub(in crate::formats::http) fn should_redact_path(url: &Url, policy: UrlPathPolicy) -> bool {
    policy == UrlPathPolicy::Redact
        && if url.cannot_be_a_base() {
            !url.path().is_empty()
        } else {
            url.path() != "/"
        }
}
