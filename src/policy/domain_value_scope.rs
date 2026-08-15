// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! RAII scope for one admitted domain value.

use super::DomainTraversalAdmission;
use super::RedactionSession;

/// Owns one active domain-value depth and exposes pre-access admission checks.
///
/// Dropping the scope restores active depth even during early returns or
/// formatter errors. It does not restore cumulative node or collection-item
/// charges. The exclusive session borrow prevents nested traversal from
/// replacing the shared session budget.
#[must_use = "retain the scope while rendering the admitted domain value"]
#[derive(Debug)]
pub struct DomainValueScope<'session, 'policy> {
    session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> DomainValueScope<'session, 'policy> {
    /// Creates a scope after its domain value has already been charged.
    #[inline]
    pub(crate) const fn new(
        session: &'session mut RedactionSession<'policy>,
    ) -> Self {
        Self { session }
    }

    /// Charges one domain node before a field is read or formatted.
    ///
    /// [`DomainTraversalAdmission::Render`] permits access to exactly the field
    /// being admitted. [`DomainTraversalAdmission::LimitReached`] permanently
    /// closes domain traversal for the session, and the field must not be read.
    #[inline]
    pub fn admit_field(&mut self) -> DomainTraversalAdmission {
        self.session.domain_budget.admit_field()
    }

    /// Charges one collection item before advancing its iterator.
    ///
    /// [`DomainTraversalAdmission::Render`] permits one iterator advancement.
    /// [`DomainTraversalAdmission::LimitReached`] permanently closes domain
    /// traversal, and the iterator must not be advanced.
    #[inline]
    pub fn admit_collection_item(&mut self) -> DomainTraversalAdmission {
        self.session.domain_budget.admit_collection_item()
    }

    /// Reborrows the shared redaction session for nested rendering.
    ///
    /// Nested domain values must call [`RedactionSession::enter_domain_value`]
    /// on this session so their charges accumulate in the same budget.
    #[inline(always)]
    pub fn session(&mut self) -> &mut RedactionSession<'policy> {
        self.session
    }
}

impl Drop for DomainValueScope<'_, '_> {
    /// Restores the active depth while preserving cumulative resource charges.
    #[inline]
    fn drop(&mut self) {
        self.session.domain_budget.leave_value();
    }
}
