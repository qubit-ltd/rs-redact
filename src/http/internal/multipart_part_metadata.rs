// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsed metadata for one multipart part.

use super::{
    content_type,
    header_parameter::{leading_token, parse_parameters},
};

/// Holds the field identity, filename evidence, and media type of one part.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the media type borrowed from the part headers.
#[must_use]
pub(in crate::http) struct MultipartPartMetadata<'a> {
    /// Non-blank form field name.
    name: Option<String>,
    /// Filename or extended filename evidence.
    filename: Option<String>,
    /// Optional borrowed part media type.
    content_type: Option<&'a str>,
}

impl<'a> MultipartPartMetadata<'a> {
    /// Parses strict disposition parameters and optional media type.
    ///
    /// # Parameters
    ///
    /// * `disposition` - Optional Content-Disposition header text.
    /// * `content_type` - Optional part Content-Type text.
    /// * `require_form_data` - Whether disposition must be `form-data`.
    ///
    /// # Returns
    ///
    /// Parsed metadata, or `None` for malformed or duplicate parameters.
    #[must_use]
    #[inline]
    pub(super) fn parse(
        disposition: Option<&str>,
        content_type: Option<&'a str>,
        require_form_data: bool,
    ) -> Option<Self> {
        if content_type.is_some_and(|value| !content_type::is_valid(value)) {
            return None;
        }
        let [name, filename, extended] = match disposition {
            Some(disposition) => {
                let disposition_kind = leading_token(disposition)?;
                if require_form_data && !disposition_kind.eq_ignore_ascii_case("form-data") {
                    return None;
                }
                parse_parameters(disposition, ["name", "filename", "filename*"])?
            }
            None if require_form_data => return None,
            None => [None, None, None],
        };
        Some(Self {
            name: name.filter(|value| !value.trim().is_empty()),
            filename: filename.or(extended),
            content_type,
        })
    }

    /// Returns the parsed field name.
    ///
    /// # Returns
    ///
    /// A non-blank field name when present.
    #[must_use]
    #[inline(always)]
    pub(super) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns filename evidence.
    ///
    /// # Returns
    ///
    /// A filename or extended filename when present.
    #[must_use]
    #[inline(always)]
    pub(super) fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Returns the part media type.
    ///
    /// # Returns
    ///
    /// Borrowed Content-Type text when present.
    #[must_use]
    #[inline(always)]
    pub(super) const fn content_type(&self) -> Option<&'a str> {
        self.content_type
    }
}
