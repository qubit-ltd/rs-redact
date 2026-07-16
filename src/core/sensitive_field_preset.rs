// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use super::SensitivityLevel;

/// Predefined groups of sensitive field names.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveFieldPreset {
    /// Passwords, client secrets, private keys, and secret-like names.
    Credentials,
    /// API keys, access tokens, refresh tokens, and JWT-like names.
    AuthTokens,
    /// HTTP authentication and cookie fields.
    Http,
    /// Session identifiers and session tokens.
    Session,
}

/// Field names for [`SensitiveFieldPreset::Credentials`].
pub const CREDENTIALS_FIELDS: [(&str, SensitivityLevel); 11] = [
    ("password", SensitivityLevel::Secret),
    ("password_confirmation", SensitivityLevel::Secret),
    ("passwd", SensitivityLevel::Secret),
    ("secret", SensitivityLevel::Secret),
    ("client_secret", SensitivityLevel::Secret),
    ("private_key", SensitivityLevel::Secret),
    ("security_key", SensitivityLevel::Secret),
    ("secret_key", SensitivityLevel::Secret),
    ("secret_access_key", SensitivityLevel::Secret),
    ("access_key", SensitivityLevel::High),
    ("access_key_id", SensitivityLevel::Medium),
];

/// Field names for [`SensitiveFieldPreset::AuthTokens`].
pub const AUTH_TOKEN_FIELDS: [(&str, SensitivityLevel); 9] = [
    ("api_key", SensitivityLevel::High),
    ("x_api_key", SensitivityLevel::High),
    ("token", SensitivityLevel::High),
    ("access_token", SensitivityLevel::High),
    ("refresh_token", SensitivityLevel::High),
    ("id_token", SensitivityLevel::High),
    ("jwt", SensitivityLevel::High),
    ("jwt_token", SensitivityLevel::High),
    ("auth_token", SensitivityLevel::High),
];

/// Field names for [`SensitiveFieldPreset::Http`].
pub const HTTP_FIELDS: [(&str, SensitivityLevel); 4] = [
    ("authorization", SensitivityLevel::High),
    ("proxy_authorization", SensitivityLevel::High),
    ("cookie", SensitivityLevel::High),
    ("set_cookie", SensitivityLevel::High),
];

/// Field names for [`SensitiveFieldPreset::Session`].
pub const SESSION_FIELDS: [(&str, SensitivityLevel); 3] = [
    ("session", SensitivityLevel::Medium),
    ("session_id", SensitivityLevel::Medium),
    ("session_token", SensitivityLevel::High),
];

impl SensitiveFieldPreset {
    /// Returns the canonical field names and levels for this preset.
    ///
    /// # Returns
    ///
    /// The static field-name and sensitivity-level pairs in the preset.
    #[must_use]
    #[inline(always)]
    pub const fn fields(self) -> &'static [(&'static str, SensitivityLevel)] {
        match self {
            Self::Credentials => &CREDENTIALS_FIELDS,
            Self::AuthTokens => &AUTH_TOKEN_FIELDS,
            Self::Http => &HTTP_FIELDS,
            Self::Session => &SESSION_FIELDS,
        }
    }
}
