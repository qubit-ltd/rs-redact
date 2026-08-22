// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-rendering sensitivity inspection for URI components.

use fluent_uri::Uri;

use super::UriFragmentPolicy;
use super::UriPathPolicy;
use super::redaction::decode_uri_component;
use super::uri_redaction_writer::admit_uri_structure;
use crate::RedactionReason;
use crate::RedactionSession;
use crate::Sensitivity;
use crate::policy::ResolvedField;

/// Parses and completely classifies one URI under the active policy.
pub(crate) fn inspect_uri(session: &mut RedactionSession, input: &str) {
    if !session.admit_input(input.len()) || !admit_uri_structure(session, input) {
        return;
    }
    let Ok(parsed) = Uri::<&str>::parse(input) else {
        session.fail_inspection(RedactionReason::InvalidUri);
        return;
    };
    if let Some(authority) = parsed.authority()
        && inspect_authority(session, authority.as_str()).is_err()
    {
        session.fail_inspection(RedactionReason::InvalidUri);
        return;
    }
    let path = parsed.path().as_str();
    if session.policy().path_policy() == UriPathPolicy::Redact && !path.is_empty() && path != "/" {
        session.observe_sensitivity(Sensitivity::High);
    }
    if let Some(query) = parsed.query()
        && inspect_query(session, query.as_str()).is_err()
    {
        session.fail_inspection(RedactionReason::InvalidUri);
        return;
    }
    if let Some(fragment) = parsed.fragment()
        && session.policy().fragment_policy() == UriFragmentPolicy::Redact
        && !fragment.as_str().is_empty()
    {
        session.observe_sensitivity(Sensitivity::High);
    }
}

/// Classifies username and password components after strict percent decoding.
fn inspect_authority(session: &mut RedactionSession, authority: &str) -> Result<(), ()> {
    let Some((userinfo, _)) = authority.rsplit_once('@') else {
        return Ok(());
    };
    let (username, password) = userinfo
        .split_once(':')
        .map_or((userinfo, None), |(username, password)| (username, Some(password)));
    inspect_named_component(session, "username", username)?;
    if let Some(password) = password {
        inspect_named_component(session, "password", password)?;
    }
    Ok(())
}

/// Classifies URI query values after strict percent decoding.
fn inspect_query(session: &mut RedactionSession, query: &str) -> Result<(), ()> {
    for pair in query.split('&') {
        let Some((raw_key, raw_value)) = pair.split_once('=') else {
            let _ = decode_uri_component(pair)?;
            continue;
        };
        let key = decode_uri_component(raw_key)?;
        let _ = decode_uri_component(raw_value)?;
        if let ResolvedField::Sensitive { sensitivity } = session.policy().resolve_field(&key) {
            session.observe_sensitivity(sensitivity);
        }
    }
    Ok(())
}

/// Classifies one decoded userinfo component by its semantic field name.
fn inspect_named_component(session: &mut RedactionSession, field: &str, raw: &str) -> Result<(), ()> {
    let _ = decode_uri_component(raw)?;
    if let ResolvedField::Sensitive { sensitivity } = session.policy().resolve_field(field) {
        session.observe_sensitivity(sensitivity);
    }
    Ok(())
}
