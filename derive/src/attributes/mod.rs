// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsing boundaries for derive, field, and Serde attributes.

mod container;
mod field;
mod internal;
mod path;
mod rename_rule;
mod representation;
mod serde;
mod serde_container;
mod serde_variant;

pub(crate) use container::ContainerAttributes;
pub(crate) use field::FieldAttributes;
pub(crate) use internal::SerdeContainerAttributeParser;
pub(crate) use internal::parse_serialize_name;
pub(crate) use path::resolve as resolve_serde_path;
pub(crate) use rename_rule::SerdeRenameRule;
pub(crate) use representation::SerdeEnumRepresentation;
pub(crate) use serde::SerdeAttributes;
pub(crate) use serde_container::SerdeContainerAttributes;
pub(crate) use serde_variant::SerdeVariantAttributes;
