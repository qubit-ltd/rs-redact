// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Process-wide redaction configuration snapshots.

use std::sync::OnceLock;

use crate::RedactionPolicy;
use crate::global_redaction_config_already_installed::GlobalRedactionConfigAlreadyInstalled;

#[cfg(feature = "http")]
use crate::http::HttpRedactionPolicy;
#[cfg(feature = "uri")]
use crate::uri::UriRedactionPolicy;

/// Immutable optional process-wide defaults for redaction components.
///
/// Applications that choose to use this configuration should install it once
/// during startup, before constructing default-derived policy snapshots. An
/// installed value affects only future snapshots; it never mutates policies
/// that already exist. Libraries must not install or replace their host
/// application's global configuration.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalRedactionConfig {
    policy: RedactionPolicy,
    #[cfg(feature = "http")]
    http_policy: HttpRedactionPolicy,
    #[cfg(feature = "uri")]
    uri_policy: UriRedactionPolicy,
}

static GLOBAL_CONFIG: OnceLock<GlobalRedactionConfig> = OnceLock::new();

impl GlobalRedactionConfig {
    /// Returns the built-in conservative configuration.
    #[inline]
    pub fn standard() -> Self {
        Self::from_policy(RedactionPolicy::standard())
    }

    /// Creates a configuration from a core policy.
    ///
    /// When the `http` or `uri` feature is enabled, the corresponding policy
    /// is derived from the supplied core policy.
    #[inline]
    pub fn from_policy(policy: RedactionPolicy) -> Self {
        Self {
            #[cfg(feature = "http")]
            http_policy: HttpRedactionPolicy::builder_from(&policy)
                .build()
                .expect("a policy snapshot must produce a valid HTTP policy"),
            #[cfg(feature = "uri")]
            uri_policy: UriRedactionPolicy::builder_from(&policy)
                .build()
                .expect("a policy snapshot must produce a valid URI policy"),
            policy,
        }
    }

    /// Replaces the derived HTTP policy with an explicit policy.
    #[cfg(feature = "http")]
    #[inline]
    pub fn with_http_policy(
        mut self,
        http_policy: HttpRedactionPolicy,
    ) -> Self {
        self.http_policy = http_policy;
        self
    }

    /// Replaces the derived URI policy with an explicit policy.
    #[cfg(feature = "uri")]
    #[inline]
    pub fn with_uri_policy(mut self, uri_policy: UriRedactionPolicy) -> Self {
        self.uri_policy = uri_policy;
        self
    }

    /// Installs this application-level configuration exactly once.
    ///
    /// Install during application assembly before any call to [`Self::current`]
    /// or creation of a default-derived policy. The first read freezes the
    /// standard configuration in the same one-time slot, so a later install
    /// fails instead of creating split process-wide defaults. This does not
    /// retroactively affect explicit policy snapshots, and library crates
    /// should leave installation to their host application.
    pub fn install(self) -> Result<(), GlobalRedactionConfigAlreadyInstalled> {
        GLOBAL_CONFIG
            .set(self)
            .map_err(|_| GlobalRedactionConfigAlreadyInstalled)
    }

    /// Returns the installed configuration.
    ///
    /// The first call freezes the standard configuration when the application
    /// has not installed one yet. Any later [`Self::install`] then fails.
    #[inline]
    pub fn current() -> &'static Self {
        GLOBAL_CONFIG.get_or_init(Self::standard)
    }

    /// Returns the core redaction policy snapshot.
    #[inline]
    pub const fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Returns the HTTP redaction policy snapshot.
    #[cfg(feature = "http")]
    #[inline]
    pub const fn http_policy(&self) -> &HttpRedactionPolicy {
        &self.http_policy
    }

    /// Returns the URI redaction policy snapshot.
    #[cfg(feature = "uri")]
    #[inline]
    pub const fn uri_policy(&self) -> &UriRedactionPolicy {
        &self.uri_policy
    }
}

impl Default for GlobalRedactionConfig {
    #[inline]
    fn default() -> Self {
        Self::standard()
    }
}
