// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixtures covering supported redacted Serde shapes.

#![allow(dead_code)]

use qubit_redact_derive::Redact;

/// Newtype whose only field is omitted.
#[derive(Redact)]
#[redact(serde)]
struct SkippedNewtype(#[redact(skip)] String);

/// Externally tagged shapes with empty and skipped payloads.
#[derive(Redact)]
#[redact(serde)]
enum ExternalCoverage {
    /// Omitted newtype payload becomes a unit variant.
    SkippedNewtype(#[redact(skip)] String),
    /// Omitted named fields retain an empty object shape.
    EmptyNamed {
        /// Omitted field.
        #[redact(skip)]
        hidden: String,
    },
    /// Omitted tuple fields retain an empty tuple shape.
    EmptyTuple(#[redact(skip)] String, #[serde(skip)] String),
    /// Skipped tuple variant exercises wildcard matching.
    #[serde(skip)]
    HiddenTuple(String),
    /// Skipped unit variant exercises unit wildcard matching.
    #[serde(skip)]
    HiddenUnit,
}

/// Nested payload used by an internally tagged newtype.
#[derive(Redact)]
#[redact(serde)]
struct InternalPayload {
    /// Plain serializable content.
    value: String,
}

/// Internally tagged newtype with no serializable carrier.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum InternalCoverage {
    /// Named content is merged beside the tag.
    Named {
        /// Plain serialized field.
        value: String,
    },
    /// Omitted content leaves only the tag.
    Empty(#[redact(skip)] String),
    /// Nested newtype content is merged beside the tag.
    Nested(#[redact(nested)] InternalPayload),
    /// Unit content contains only the tag.
    Ready,
}

/// Adjacently tagged shapes with no serializable carriers.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "payload")]
enum AdjacentCoverage {
    /// Empty named content uses a zero-field proxy.
    EmptyNamed {
        /// Omitted field.
        #[redact(skip)]
        hidden: String,
    },
    /// Empty tuple content uses a zero-element proxy.
    EmptyTuple(#[redact(skip)] String, #[serde(skip)] String),
    /// Empty newtype content omits the content member.
    EmptyNewtype(#[redact(skip)] String),
}

/// Untagged newtype paths with and without a carrier.
#[derive(Redact)]
#[redact(serde)]
#[serde(untagged)]
enum UntaggedCoverage {
    /// Omitted content serializes as a unit.
    Empty(#[redact(skip)] String),
    /// Plain content serializes directly.
    Value(String),
}

/// Directional field rename uses only the serialization branch.
#[derive(Redact)]
#[redact(serde)]
#[serde(rename(serialize = "DirectionalRecord", deserialize = "InputRecord"))]
struct DirectionalRecord {
    /// Explicit directional serialized name.
    #[serde(rename(serialize = "outputValue", deserialize = "inputValue"))]
    value: String,
    /// A deserialize-only rename leaves the serialized Rust field name intact.
    #[serde(rename(deserialize = "legacyValue"))]
    plain_value: String,
}

/// Directional container and variant rules use their serialization branches.
#[derive(Redact)]
#[redact(serde)]
#[serde(
    rename_all(serialize = "snake_case", deserialize = "camelCase"),
    rename_all_fields(serialize = "camelCase", deserialize = "snake_case")
)]
enum DirectionalEnum {
    /// Variant-local directionality covers rename and named-field rules.
    #[serde(
        rename(serialize = "ready_output", deserialize = "readyInput"),
        rename_all(serialize = "kebab-case", deserialize = "camelCase")
    )]
    ReadyValue {
        /// Field name transformed by the serialization-side variant rule.
        field_value: String,
    },
}

macro_rules! rename_enum {
    ($name:ident, $rule:literal) => {
        /// Enum using one supported variant rename rule.
        #[derive(Redact)]
        #[redact(serde)]
        #[serde(rename_all = $rule)]
        enum $name {
            /// Mixed-case variant used to distinguish rename rules.
            SomeValue,
        }
    };
}

rename_enum!(LowercaseVariants, "lowercase");
rename_enum!(UppercaseVariants, "UPPERCASE");
rename_enum!(PascalVariants, "PascalCase");
rename_enum!(CamelVariants, "camelCase");
rename_enum!(SnakeVariants, "snake_case");
rename_enum!(ScreamingSnakeVariants, "SCREAMING_SNAKE_CASE");
rename_enum!(KebabVariants, "kebab-case");
rename_enum!(ScreamingKebabVariants, "SCREAMING-KEBAB-CASE");

/// Compile-only fixture entrypoint.
fn main() {}
