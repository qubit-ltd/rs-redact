// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parser-neutral URI component helpers.

mod percent_encoded_field_name;

#[cfg(feature = "uri")]
mod uri_component;
#[cfg(feature = "uri")]
mod uri_fragment_policy;
#[cfg(feature = "uri")]
mod uri_path_policy;
#[cfg(feature = "uri")]
mod uri_redaction;
#[cfg(feature = "uri")]
mod uri_redaction_policy;
#[cfg(feature = "uri")]
mod uri_redaction_policy_builder;
#[cfg(feature = "uri")]
mod uri_redaction_policy_inner;
#[cfg(feature = "uri")]
mod uri_redaction_reason;
#[cfg(feature = "uri")]
mod uri_redaction_status;
#[cfg(feature = "uri")]
mod uri_redactor;

pub use percent_encoded_field_name::decode_percent_encoded_field_name;

#[cfg(feature = "uri")]
pub use uri_component::UriComponent;
#[cfg(feature = "uri")]
pub use uri_fragment_policy::UriFragmentPolicy;
#[cfg(feature = "uri")]
pub use uri_path_policy::UriPathPolicy;
#[cfg(feature = "uri")]
pub use uri_redaction::UriRedaction;
#[cfg(feature = "uri")]
pub use uri_redaction_policy::UriRedactionPolicy;
#[cfg(feature = "uri")]
pub use uri_redaction_policy_builder::UriRedactionPolicyBuilder;
#[cfg(feature = "uri")]
pub use uri_redaction_reason::UriRedactionReason;
#[cfg(feature = "uri")]
pub use uri_redaction_status::UriRedactionStatus;
#[cfg(feature = "uri")]
pub use uri_redactor::UriRedactor;
