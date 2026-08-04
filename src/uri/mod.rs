// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy-driven URI redaction.

mod internal;
mod uri_component;
mod uri_fragment_policy;
mod uri_inspection;
mod uri_path_policy;
mod uri_redaction;
mod uri_redaction_policy;
mod uri_redaction_policy_builder;
mod uri_redaction_policy_inner;
mod uri_redaction_reason;
mod uri_redaction_status;
mod uri_redactor;
pub use uri_component::UriComponent;
pub use uri_fragment_policy::UriFragmentPolicy;
pub use uri_inspection::UriInspection;
pub use uri_path_policy::UriPathPolicy;
pub use uri_redaction::UriRedaction;
pub use uri_redaction_policy::UriPolicy;
pub(crate) use uri_redaction_policy_builder::UriPolicyBuilder;
pub use uri_redaction_reason::UriRedactionReason;
pub use uri_redaction_status::UriRedactionStatus;
pub use uri_redactor::UriRedactor;
