// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsed metadata for one multipart body part.

use super::parse_header_parameters;

/// Metadata parsed from one multipart part's headers.
#[must_use]
pub(in crate::adapter::http) struct MultipartPartMetadata<'a> {
    /// Original field name used for sensitivity matching.
    name: Option<String>,
    /// Filename evidence from `filename` or `filename*`.
    filename: Option<String>,
    /// Borrowed part-level content type text.
    content_type: Option<&'a str>,
}

impl<'a> MultipartPartMetadata<'a> {
    /// Parses metadata from a content disposition and optional content type.
    ///
    /// # Parameters
    ///
    /// * `content_disposition` - Part-level `Content-Disposition` text.
    /// * `content_type` - Optional part-level `Content-Type` text.
    ///
    /// # Returns
    ///
    /// Parsed metadata, or `None` when a requested disposition parameter is
    /// malformed or duplicated.
    #[inline(always)]
    pub(in crate::adapter::http) fn parse(
        content_disposition: &str,
        content_type: Option<&'a str>,
    ) -> Option<Self> {
        let [name, filename, extended_filename] = parse_header_parameters(
            content_disposition,
            ["name", "filename", "filename*"],
        )?;
        Some(Self {
            name,
            filename: filename.or(extended_filename),
            content_type,
        })
    }

    /// Returns the original multipart field name.
    ///
    /// # Returns
    ///
    /// `Some` with the parsed name, or `None` when no name was supplied.
    #[inline(always)]
    pub(in crate::adapter::http) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns filename evidence for the part.
    ///
    /// # Returns
    ///
    /// `Some` when `filename` or `filename*` was supplied, otherwise `None`.
    #[inline(always)]
    pub(in crate::adapter::http) fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Returns the part-level content type.
    ///
    /// # Returns
    ///
    /// Borrowed content type text, or `None` when the header was absent.
    #[inline(always)]
    pub(in crate::adapter::http) const fn content_type(
        &self,
    ) -> Option<&'a str> {
        self.content_type
    }
}
