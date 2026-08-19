// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private support for domain-object redaction.

mod domain_redaction_context;
mod nested;

pub(crate) use domain_redaction_context::DomainEntry;
pub(crate) use domain_redaction_context::DomainRedactionContext;
