// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private helpers for parsing Serde attributes.

mod container_parser;
mod directional_name;

pub(crate) use container_parser::SerdeContainerAttributeParser;
pub(crate) use directional_name::parse_serialize_name;
