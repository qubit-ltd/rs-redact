// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
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
pub fn canonicalize_field_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|ch| !matches!(ch, '_' | '-' | '.') && !ch.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}
