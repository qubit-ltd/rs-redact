// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Built-in groups of sensitive field names.

use super::Sensitivity;

/// Predefined groups of sensitive field names.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveFieldPreset {
    /// Passwords, client secrets, private keys, and secret-like names.
    Credentials,
    /// Connection strings and configuration values that embed credentials.
    CredentialContainers,
    /// API keys, access tokens, refresh tokens, and JWT-like names.
    AuthTokens,
    /// HTTP authentication and cookie fields.
    Http,
    /// Session identifiers and session tokens.
    Session,
}

/// Field names for [`SensitiveFieldPreset::Credentials`].
const CREDENTIALS_FIELDS: [(&str, Sensitivity); 13] = [
    ("password", Sensitivity::Secret),
    ("password_confirmation", Sensitivity::Secret),
    ("passwd", Sensitivity::Secret),
    ("passphrase", Sensitivity::Secret),
    ("pgpassword", Sensitivity::Secret),
    ("secret", Sensitivity::Secret),
    ("client_secret", Sensitivity::Secret),
    ("private_key", Sensitivity::Secret),
    ("security_key", Sensitivity::Secret),
    ("secret_key", Sensitivity::Secret),
    ("secret_access_key", Sensitivity::Secret),
    ("access_key", Sensitivity::High),
    ("access_key_id", Sensitivity::Medium),
];

/// Field names for [`SensitiveFieldPreset::CredentialContainers`].
const CREDENTIAL_CONTAINER_FIELDS: [(&str, Sensitivity); 11] = [
    ("dsn", Sensitivity::Secret),
    ("database_dsn", Sensitivity::Secret),
    ("redis_url", Sensitivity::Secret),
    ("mongodb_uri", Sensitivity::Secret),
    ("mongodb_url", Sensitivity::Secret),
    ("amqp_url", Sensitivity::Secret),
    ("broker_url", Sensitivity::Secret),
    ("http_proxy", Sensitivity::Secret),
    ("https_proxy", Sensitivity::Secret),
    ("all_proxy", Sensitivity::Secret),
    ("docker_auth_config", Sensitivity::Secret),
];

/// Field names for [`SensitiveFieldPreset::AuthTokens`].
const AUTH_TOKEN_FIELDS: [(&str, Sensitivity); 9] = [
    ("api_key", Sensitivity::High),
    ("x_api_key", Sensitivity::High),
    ("token", Sensitivity::High),
    ("access_token", Sensitivity::High),
    ("refresh_token", Sensitivity::High),
    ("id_token", Sensitivity::High),
    ("jwt", Sensitivity::High),
    ("jwt_token", Sensitivity::High),
    ("auth_token", Sensitivity::High),
];

/// Field names for [`SensitiveFieldPreset::Http`].
const HTTP_FIELDS: [(&str, Sensitivity); 4] = [
    ("authorization", Sensitivity::High),
    ("proxy_authorization", Sensitivity::High),
    ("cookie", Sensitivity::High),
    ("set_cookie", Sensitivity::High),
];

/// Field names for [`SensitiveFieldPreset::Session`].
const SESSION_FIELDS: [(&str, Sensitivity); 3] = [
    ("session", Sensitivity::High),
    ("session_id", Sensitivity::High),
    ("session_token", Sensitivity::High),
];

impl SensitiveFieldPreset {
    /// Returns the static canonical field-name and sensitivity pairs in this
    /// preset.
    ///
    /// # Returns
    ///
    /// The complete static field table for this preset.
    #[inline(always)]
    pub const fn fields(self) -> &'static [(&'static str, Sensitivity)] {
        match self {
            Self::Credentials => &CREDENTIALS_FIELDS,
            Self::CredentialContainers => &CREDENTIAL_CONTAINER_FIELDS,
            Self::AuthTokens => &AUTH_TOKEN_FIELDS,
            Self::Http => &HTTP_FIELDS,
            Self::Session => &SESSION_FIELDS,
        }
    }
}
