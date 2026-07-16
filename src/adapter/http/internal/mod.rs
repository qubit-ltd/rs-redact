// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private HTTP parsing types.

pub(super) mod body_input_kind;
pub(super) mod header_parameter;
pub(super) mod multipart_delimiter;
pub(super) mod multipart_part_metadata;
pub(super) mod multipart_sanitization;

pub(super) use body_input_kind::BodyInputKind;
pub(super) use header_parameter::{
    HeaderParameter,
    parse_header_parameters,
};
pub(super) use multipart_delimiter::MultipartDelimiter;
pub(super) use multipart_part_metadata::MultipartPartMetadata;
pub(super) use multipart_sanitization::MultipartSanitization;
