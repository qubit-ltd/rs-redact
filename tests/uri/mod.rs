// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mirrored integration tests for URI helpers.

#[cfg(feature = "uri")]
mod internal;
#[cfg(feature = "uri")]
mod uri_component_tests;
#[cfg(feature = "uri")]
mod uri_fragment_policy_tests;
#[cfg(feature = "uri")]
mod uri_inspection_tests;
#[cfg(feature = "uri")]
mod uri_path_policy_tests;
#[cfg(feature = "uri")]
mod uri_redaction_policy_builder_tests;
#[cfg(feature = "uri")]
mod uri_redaction_policy_inner_tests;
#[cfg(feature = "uri")]
mod uri_redaction_policy_tests;
#[cfg(feature = "uri")]
mod uri_redaction_reason_tests;
#[cfg(feature = "uri")]
mod uri_redaction_session_tests;
#[cfg(feature = "uri")]
mod uri_redaction_status_tests;
#[cfg(feature = "uri")]
mod uri_redaction_tests;
#[cfg(feature = "uri")]
mod uri_redactor_tests;
