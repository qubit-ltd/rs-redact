// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy-driven URI redaction.

pub(crate) mod inspection;
mod internal;
mod redaction;
mod uri_fragment_policy;
mod uri_path_policy;
mod uri_redaction_policy;
mod uri_redaction_policy_builder;
mod uri_redaction_policy_inner;
mod uri_redaction_writer;
pub use uri_fragment_policy::UriFragmentPolicy;
pub use uri_path_policy::UriPathPolicy;
pub use uri_redaction_policy::UriPolicy;
pub(crate) use uri_redaction_policy_builder::UriPolicyBuilder;
pub use uri_redaction_writer::UriRedactionWriter;
