// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Admission helpers for generated Serde structure and enum payloads.

use serde::Serializer;
use serde::ser::Error;

use super::budget_serializer::items;
use super::redact_serialize_scope::admit_input;
use super::redact_serialize_scope::admit_node;
use super::redact_serialize_scope::admit_payload;
use super::serde_node_guard::SerdeNodeGuard;

/// Admits generated container fields under the caller's shared budget.
///
/// # Errors
///
/// Returns a serializer error when the collection allowance is insufficient.
///
/// # Type Parameters
///
/// - `E`: Destination error type used to report admission failure.
///
/// # Parameters
///
/// - `count`: Generated container fields to reserve before visiting children.
///
/// # Returns
///
/// Success after the requested event or admission step completes.
#[doc(hidden)]
#[inline(always)]
pub fn admit_serialize_items<E: Error>(count: usize) -> Result<(), E> {
    items(count)
}

/// Serializes an external unit variant after admitting its scalar name.
///
/// # Errors
///
/// Returns an error if the input or logical payload budget or downstream
/// serializer rejects the variant payload.
///
/// # Type Parameters
///
/// - `S`: Destination serializer.
///
/// # Parameters
///
/// - `serializer`: Destination receiving the admitted unit variant.
/// - `name`: Static source enum name, excluded from scalar payload.
/// - `index`: Source variant index.
/// - `variant`: Variant label charged as source and scalar payload.
///
/// # Returns
///
/// The downstream result after the admitted representation is serialized.
#[doc(hidden)]
pub fn serialize_unit_variant<S: Serializer>(
    serializer: S,
    name: &'static str,
    index: u32,
    variant: &'static str,
) -> Result<S::Ok, S::Error> {
    if !admit_input(variant.len()) || !admit_payload(variant.len()) {
        return Err(Error::custom("redaction enum payload budget exceeded"));
    }
    serializer.serialize_unit_variant(name, index, variant)
}

/// Enters a generated content proxy without opening another policy scope.
///
/// # Errors
///
/// Returns an error when the structural allowance or the content serializer
/// rejects the payload.
///
/// # Type Parameters
///
/// - `S`: Destination serializer.
/// - `F`: One-shot callback encoding the content in the current policy scope.
///
/// # Parameters
///
/// - `serializer`: Destination receiving the admitted content.
/// - `body`: Called once only after content-node admission.
///
/// # Returns
///
/// The downstream result after the admitted representation is serialized.
#[doc(hidden)]
pub fn serialize_content<S, F>(serializer: S, body: F) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    F: FnOnce(S) -> Result<S::Ok, S::Error>,
{
    if !admit_node() {
        return Err(Error::custom("redaction content structural budget exceeded"));
    }
    let _node = SerdeNodeGuard;
    body(serializer)
}

/// Admits generated fields using the destination serializer's error type.
///
/// # Errors
///
/// Returns an error when the collection allowance is insufficient.
///
/// # Type Parameters
///
/// - `S`: Destination serializer defining the admission error type.
///
/// # Parameters
///
/// - `_`: Destination reference used only to determine its error type.
/// - `count`: Generated container fields to reserve before visiting children.
///
/// # Returns
///
/// Success after the requested event or admission step completes.
#[doc(hidden)]
#[inline(always)]
pub fn admit_serializer_items<S: Serializer>(_: &S, count: usize) -> Result<(), S::Error> {
    admit_serialize_items(count)
}
