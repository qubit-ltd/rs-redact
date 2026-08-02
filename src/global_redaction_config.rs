// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Process-wide redaction configuration snapshots.

use std::sync::{
    LazyLock,
    OnceLock,
};

use crate::RedactionPolicy;
use crate::global_redaction_config_already_installed::GlobalRedactionConfigAlreadyInstalled;

#[cfg(feature = "http")]
use crate::http::HttpRedactionPolicy;

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
}

static STANDARD_CONFIG: LazyLock<GlobalRedactionConfig> =
    LazyLock::new(GlobalRedactionConfig::standard);
static GLOBAL_CONFIG: OnceLock<GlobalRedactionConfig> = OnceLock::new();

impl GlobalRedactionConfig {
    /// Returns the built-in conservative configuration.
    #[inline]
    pub fn standard() -> Self {
        Self::from_policy(RedactionPolicy::standard())
    }

    /// Creates a configuration from a core policy.
    ///
    /// When the `http` feature is enabled, the HTTP policy is derived from
    /// the supplied core policy.
    #[inline]
    pub fn from_policy(policy: RedactionPolicy) -> Self {
        Self {
            #[cfg(feature = "http")]
            http_policy: HttpRedactionPolicy::builder_from(&policy)
                .build()
                .expect("a policy snapshot must produce a valid HTTP policy"),
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

    /// Installs this application-level configuration exactly once.
    ///
    /// Install during application assembly before creating default-derived
    /// policies. This does not retroactively affect existing snapshots, and
    /// library crates should leave installation to their host application.
    pub fn install(self) -> Result<(), GlobalRedactionConfigAlreadyInstalled> {
        GLOBAL_CONFIG
            .set(self)
            .map_err(|_| GlobalRedactionConfigAlreadyInstalled)
    }

    /// Returns the installed configuration, or the standard configuration
    /// when no installation has occurred.
    #[inline]
    pub fn current() -> &'static Self {
        GLOBAL_CONFIG.get().unwrap_or(&STANDARD_CONFIG)
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
}

impl Default for GlobalRedactionConfig {
    #[inline]
    fn default() -> Self {
        Self::standard()
    }
}
