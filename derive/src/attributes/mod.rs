// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsing boundaries for derive, field, and Serde attributes.

mod container_attributes;
mod field_attributes;
mod internal;
mod serde_attributes;
mod serde_container_attributes;
mod serde_enum_representation;
mod serde_rename_rule;
mod serde_variant_attributes;

pub(crate) use container_attributes::ContainerAttributes;
pub(crate) use field_attributes::FieldAttributes;
pub(crate) use internal::SerdeContainerAttributeParser;
pub(crate) use internal::parse_serialize_name;
pub(crate) use serde_attributes::SerdeAttributes;
pub(crate) use serde_container_attributes::SerdeContainerAttributes;
pub(crate) use serde_enum_representation::SerdeEnumRepresentation;
pub(crate) use serde_rename_rule::SerdeRenameRule;
pub(crate) use serde_variant_attributes::SerdeVariantAttributes;
