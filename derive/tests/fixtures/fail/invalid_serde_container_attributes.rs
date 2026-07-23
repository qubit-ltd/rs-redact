// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixtures for malformed Serde container controls.

use qubit_redact_derive::Redact;

/// Serde container controls must use list syntax.
#[derive(Redact)]
#[redact(serde)]
#[serde]
struct PathAttribute;

/// Container renames may be specified once.
#[derive(Redact)]
#[redact(serde)]
#[serde(rename = "first", rename = "second")]
struct DuplicateRename;

/// Container field rename rules may be specified once.
#[derive(Redact)]
#[redact(serde)]
#[serde(rename_all = "camelCase", rename_all = "snake_case")]
struct DuplicateRenameAll {
    /// Named field.
    some_value: String,
}

/// Variant-field rules are enum-only.
#[derive(Redact)]
#[redact(serde)]
#[serde(rename_all_fields = "camelCase")]
struct StructRenameAllFields {
    /// Named field.
    some_value: String,
}

/// Enum variant-field rules may be specified once.
#[derive(Redact)]
#[redact(serde)]
#[serde(
    rename_all_fields = "camelCase",
    rename_all_fields = "snake_case"
)]
enum DuplicateRenameAllFields {
    /// Named variant.
    Value {
        /// Named field.
        some_value: String,
    },
}

/// Tags are enum-only.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
struct StructTag;

/// Content fields are enum-only.
#[derive(Redact)]
#[redact(serde)]
#[serde(content = "payload")]
struct StructContent;

/// Untagged mode is enum-only.
#[derive(Redact)]
#[redact(serde)]
#[serde(untagged)]
struct StructUntagged;

/// Untagged must be bare.
#[derive(Redact)]
#[redact(serde)]
#[serde(untagged = true)]
enum AssignedUntagged {
    /// Unit variant.
    Value,
}

/// Untagged may be specified once.
#[derive(Redact)]
#[redact(serde)]
#[serde(untagged, untagged)]
enum DuplicateUntagged {
    /// Unit variant.
    Value,
}

/// Structural container controls are outside the redacted allowlist.
#[derive(Redact)]
#[redact(serde)]
#[serde(transparent)]
struct UnsupportedControl(String);

/// Tags may be specified once.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "first", tag = "second")]
enum DuplicateTag {
    /// Unit variant.
    Value,
}

/// Content fields may be specified once.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "first", content = "second")]
enum DuplicateContent {
    /// Unit variant.
    Value,
}

/// Content requires a tag.
#[derive(Redact)]
#[redact(serde)]
#[serde(content = "payload")]
enum ContentWithoutTag {
    /// Unit variant.
    Value,
}

/// Untagged cannot be combined with tagged representations.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", untagged)]
enum UntaggedWithTag {
    /// Unit variant.
    Value,
}

/// Adjacent tag and content names must be distinct.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "kind")]
enum EqualTagAndContent {
    /// Unit variant.
    Value,
}

/// Rename rules use Serde's exact supported spellings.
#[derive(Redact)]
#[redact(serde)]
#[serde(rename_all = "title-case")]
struct UnsupportedRenameRule {
    /// Named field.
    some_value: String,
}

/// Internal tags must not collide with serialized field names.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum ConflictingInternalTag {
    /// Named variant.
    Value {
        /// Conflicts with the internal tag.
        kind: String,
    },
}

/// Internally tagged enums cannot contain tuple variants.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum InternalTagWithTupleVariant {
    /// Tuple variants cannot merge the internal tag.
    Value(String, String),
}

/// Keeps every invalid type reachable.
fn main() {}
