// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-destructive redaction contract for domain objects.

use std::fmt;
use std::fmt::Formatter;

use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::domain::Redacted;

/// Writes the unquoted safe marker for a domain branch that was not admitted.
///
/// The marker is structural output rather than a string field value, so its
/// [`fmt::Debug`] representation deliberately omits quotes. Domain formatters
/// use it as the terminal field, element, or map entry after a node, item, or
/// depth limit is reached. The surrounding bounded formatter still charges the
/// marker against the shared output budget.
pub struct DomainTruncated;

impl fmt::Debug for DomainTruncated {
    /// Writes the complete unquoted structural truncation marker.
    #[inline(always)]
    #[must_use]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("<truncated>")
    }
}

/// Formats a domain object through an explicit immutable redaction policy.
///
/// Implementations must write only the redacted representation from
/// [`Self::fmt_redacted`]. The original object remains unchanged.
/// Domain owners remain responsible for deciding which fields are sensitive
/// and for selecting the redaction boundary. This trait does not infer that a
/// newly added field needs redaction.
///
/// Pure domain formatting consumes output bytes and domain structure budget,
/// but never consumes diagnostic input bytes. An adapter that inspects encoded
/// input, such as JSON or HTTP, must charge the exact input size at its adapter
/// boundary. Implementations must enter the object before inspecting fields,
/// admit every field before reading or formatting it, and use
/// [`DomainTruncated`] when admission fails. Sensitive fields must use fixed or
/// policy-derived safe values without invoking their original `Debug` or
/// `Display` implementation. Output is bounded by the library, but arbitrary
/// user formatting logic may still perform its own computation or allocation.
///
/// # Example
///
/// ```
/// use std::fmt;
///
/// use qubit_redact::RedactionSession;
/// use qubit_redact::domain::{DomainTruncated, Redact};
/// use qubit_redact::policy::{
///     DomainTraversalAdmission,
///     DomainValueAdmission,
/// };
///
/// struct Account {
///     user: String,
///     password: String,
/// }
///
/// impl Redact for Account {
///     fn fmt_redacted(
///         &self,
///         session: &mut RedactionSession<'_>,
///         formatter: &mut fmt::Formatter<'_>,
///     ) -> fmt::Result {
///         let DomainValueAdmission::Entered(mut scope) =
///             session.enter_domain_value()
///         else {
///             return fmt::Debug::fmt(&DomainTruncated, formatter);
///         };
///         let mut output = formatter.debug_struct("Account");
///         if scope.admit_field() == DomainTraversalAdmission::LimitReached {
///             return output.field("user", &DomainTruncated).finish();
///         }
///         output.field("user", &self.user);
///         if scope.admit_field() == DomainTraversalAdmission::LimitReached {
///             return output.field("password", &DomainTruncated).finish();
///         }
///         output.field("password", &"<redacted>").finish()
///     }
/// }
///
/// let account = Account {
///     user: "ada".to_owned(),
///     password: "raw-secret".to_owned(),
/// };
/// assert_eq!(
///     format!("{:?}", account.redacted()),
///     r#"Account { user: "ada", password: "<redacted>" }"#,
/// );
/// assert_eq!(account.password, "raw-secret");
/// ```
pub trait Redact {
    /// Creates a borrowed view using a snapshot of the current default policy.
    ///
    /// # Returns
    ///
    /// A lazy redacted view borrowing this object and owning its policy
    /// snapshot.
    #[inline(always)]
    #[must_use]
    fn redacted(&self) -> Redacted<'_, Self>
    where
        Self: Sized,
    {
        Redacted::new(self, RedactionPolicy::default())
    }

    /// Creates a borrowed view using a snapshot of `policy`.
    ///
    /// # Parameters
    ///
    /// * `policy` - Policy to clone into the returned view.
    ///
    /// # Returns
    ///
    /// A lazy redacted view borrowing this object and owning the cloned policy.
    #[inline(always)]
    #[must_use]
    fn redacted_with(&self, policy: &RedactionPolicy) -> Redacted<'_, Self>
    where
        Self: Sized,
    {
        Redacted::new(self, policy.clone())
    }

    /// Writes this object's redacted debug representation.
    ///
    /// Implementations should honor the formatting flags carried by
    /// `formatter`, including alternate pretty formatting. Sensitive fields
    /// must not invoke their original `Debug` or `Display` implementations.
    /// Before accessing the object, implementations must call
    /// [`RedactionSession::enter_domain_value`], and must charge every field or
    /// collection item through the returned scope before reading it. Budget
    /// rejection is a normal business state represented by
    /// [`DomainTruncated`], not [`fmt::Error`].
    ///
    /// # Parameters
    ///
    /// * `session` - Shared diagnostic session governing this representation
    ///   and all nested values.
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the admitted redacted representation.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter cannot accept the
    /// complete representation.
    #[doc(hidden)]
    fn fmt_redacted(
        &self,
        session: &mut RedactionSession<'_>,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result;
}
