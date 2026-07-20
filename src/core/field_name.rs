// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
/// Canonicalizes a field name for sensitivity matching.
///
/// The canonical form trims the name, lowercases it, and removes common word
/// separators. This makes names like `access_token`, `access-token`,
/// `access.token`, `access Token`, and `accessToken` match the same entry.
///
/// # Parameters
///
/// * `name` - Raw field name.
///
/// # Returns
///
/// Canonical field name used as the lookup key.
#[must_use]
pub fn canonicalize_field_name(name: &str) -> String {
    crate::policy::internal::canonicalize_field_name(name)
}

/// Finds the first matching canonical form at a semantic token boundary.
///
/// Boundaries include common separators, camel-case transitions, and the
/// transition from an uppercase acronym to a capitalized word. Candidates are
/// visited from the complete name through suffixes ordered from
/// longest to shortest.
///
/// # Parameters
///
/// * `name` - Raw field name.
/// * `find` - Resolver invoked for each eligible canonical candidate.
///
/// # Returns
///
/// The first resolved value, or `None` when no suffix matches.
#[must_use]
pub(crate) fn find_canonical_field_match<T>(
    name: &str,
    mut find: impl FnMut(&str) -> Option<T>,
) -> Option<T> {
    crate::policy::internal::canonical_field_candidates(
        name,
        crate::policy::FieldNameMatching::ExactOrTokenSuffix,
    )
    .find_map(|candidate| find(&candidate))
}
