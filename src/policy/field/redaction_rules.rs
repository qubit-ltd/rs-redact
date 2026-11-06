// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field rules and their resolved floor protection.

use std::ops::ControlFlow;
use std::sync::Arc;

use super::AllowRule;
use super::FieldClassification;
use super::FieldMatchKind;
use super::FieldNameMatching;
use super::RedactionFloor;
use super::SensitiveFieldRule;
use super::Sensitivity;
use super::UnknownFieldPolicy;
use crate::policy::ResolvedField;
use crate::policy::internal::RedactionPolicyInner;
use crate::policy::internal::visit_canonical_field_candidates;

/// Immutable, cheap-to-clone field classification snapshot.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::Sensitivity;
///
/// let policy = RedactionPolicy::standard();
/// let rules = policy.rules();
/// assert_eq!(rules.sensitivity_for("password"), Some(Sensitivity::Secret));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionRules {
    /// Immutable application-owned classification rules.
    application: Arc<RedactionPolicyInner>,
    /// Optional minimum protection evaluated after application rules.
    floor: Option<RedactionFloor>,
}

impl RedactionRules {
    /// Creates immutable rules from application rules and an optional floor.
    ///
    /// # Parameters
    ///
    /// - `application`: Owned application rules to share between snapshot
    ///   clones.
    /// - `floor`: Minimum protection to attach, or `None` to disable it.
    ///
    /// # Returns
    ///
    /// A snapshot sharing the application rules and owning the optional floor.
    #[must_use]
    #[inline(always)]
    pub(crate) fn new(application: RedactionPolicyInner, floor: Option<RedactionFloor>) -> Self {
        Self {
            application: Arc::new(application),
            floor,
        }
    }

    /// Returns the attached minimum floor, if enabled.
    ///
    /// # Returns
    ///
    /// `Some(&RedactionFloor)` when a floor is enabled, or `None` when no
    /// floor is attached.
    #[must_use]
    #[inline(always)]
    pub fn floor(&self) -> Option<&RedactionFloor> {
        self.floor.as_ref()
    }

    /// Resolves final sensitivity from application and floor layers.
    ///
    /// # Parameters
    ///
    /// - `field`: Field name to classify using the application matching mode
    ///   and each floor layer's own matching mode.
    ///
    /// # Returns
    ///
    /// `Some(sensitivity)` when an application rule, application unknown-field
    /// fallback, or floor layer yields a sensitivity, using the strongest
    /// result; `None` when none of those sources yields a sensitivity.
    #[must_use]
    #[inline(always)]
    pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        match self.resolve_field(field) {
            ResolvedField::Sensitive { sensitivity } => Some(sensitivity),
            ResolvedField::PassThrough => None,
        }
    }

    /// Returns the application layer's field-name matching mode.
    ///
    /// # Returns
    ///
    /// The matching mode used by application rules. Floor layers may use a
    /// different mode.
    #[must_use]
    #[inline(always)]
    pub fn matching(&self) -> FieldNameMatching {
        self.application.matching
    }

    /// Returns the application fallback for unclassified fields.
    ///
    /// # Returns
    ///
    /// The fallback policy used by the application layer. Floor layers apply
    /// their own fallback independently.
    #[must_use]
    #[inline(always)]
    pub fn unknown_field_policy(&self) -> UnknownFieldPolicy {
        self.application.unknown_field_policy
    }

    /// Iterates only application sensitive rules, never floor rules.
    ///
    /// # Returns
    ///
    /// An iterator over the application's explicit sensitive rules. Floor
    /// rules are not included.
    #[inline]
    pub fn application_sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.application
            .sensitive
            .iter()
            .map(|(field, level)| SensitiveFieldRule::new(field, *level))
    }

    /// Iterates only application allow rules, never floor rules.
    ///
    /// # Returns
    ///
    /// An iterator over the application's exact and suffix allow rules. Floor
    /// rules are not included, and these allow rules do not bypass a floor.
    #[inline]
    pub fn application_allow_rules(&self) -> impl Iterator<Item = AllowRule<'_>> {
        self.application
            .allow_exact
            .iter()
            .map(|field| AllowRule::new(field, FieldNameMatching::Exact))
            .chain(
                self.application
                    .allow_suffix
                    .iter()
                    .map(|field| AllowRule::new(field, FieldNameMatching::ExactOrTokenSuffix)),
            )
    }

    /// Explains application-rule matching only; it is not the final safety
    /// decision.
    ///
    /// A result of [`FieldClassification::Unknown`] describes only the
    /// application layer. A floor can still classify that field, so consult
    /// [`Self::sensitivity_for`] for the final result.
    ///
    /// # Type Parameters
    ///
    /// - `'a`: Lifetime of rule names borrowed from this snapshot.
    ///
    /// # Parameters
    ///
    /// - `field`: Field name to explain against application rules.
    ///
    /// # Returns
    ///
    /// The application-layer explanation. It must not be used as the final
    /// confidentiality decision.
    ///
    /// # Examples
    ///
    /// ```
    /// use qubit_redact::{FieldClassification, RedactionFloor, RedactionPolicy, Sensitivity};
    ///
    /// let floor = RedactionFloor::builder()
    ///     .raise("provider_pin", Sensitivity::Secret)?
    ///     .build()?;
    /// let policy = RedactionPolicy::builder()
    ///     .fields(|fields| { fields.disable_floor(); })?
    ///     .build()?
    ///     .with_floor(floor);
    /// let rules = policy.rules();
    ///
    /// assert_eq!(rules.classify_field("provider_pin"), FieldClassification::Unknown);
    /// assert_eq!(rules.sensitivity_for("provider_pin"), Some(Sensitivity::Secret));
    /// # Ok::<(), qubit_redact::PolicyError>(())
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn classify_field<'a>(&'a self, field: &str) -> FieldClassification<'a> {
        classify_inner(&self.application, field, self.application.matching, true)
    }

    /// Replaces the floor for this rules snapshot.
    ///
    /// Any existing floor is discarded, so its protections no longer
    /// contribute to classification. Use [`Self::add_floor`] to retain and
    /// combine existing floor protection.
    ///
    /// # Parameters
    ///
    /// - `floor`: The floor that replaces any currently attached floor.
    ///
    /// # Returns
    ///
    /// A rules snapshot with `floor` as its only attached floor.
    ///
    /// # Examples
    ///
    /// ```
    /// use qubit_redact::{RedactionFloor, RedactionPolicy, Sensitivity};
    ///
    /// let legacy = RedactionFloor::builder()
    ///     .raise("legacy_pin", Sensitivity::Secret)?
    ///     .build()?;
    /// let provider = RedactionFloor::builder()
    ///     .raise("provider_pin", Sensitivity::Secret)?
    ///     .build()?;
    /// let policy = RedactionPolicy::builder()
    ///     .fields(|fields| { fields.disable_floor(); })?
    ///     .build()?
    ///     .with_floor(legacy);
    /// let replaced = policy.rules().clone().with_floor(provider);
    ///
    /// assert_eq!(replaced.sensitivity_for("legacy_pin"), None);
    /// assert_eq!(replaced.sensitivity_for("provider_pin"), Some(Sensitivity::Secret));
    /// # Ok::<(), qubit_redact::PolicyError>(())
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn with_floor(mut self, floor: RedactionFloor) -> Self {
        self.floor = Some(floor);
        self
    }

    /// Adds a floor without weakening an existing floor.
    ///
    /// When a floor already exists, both layers remain active and their
    /// strongest sensitivity is used. Unlike [`Self::with_floor`], this does
    /// not discard earlier floor protections.
    ///
    /// # Parameters
    ///
    /// - `floor`: Additional minimum protection to combine with the attached
    ///   floor, if any.
    ///
    /// # Returns
    ///
    /// A rules snapshot whose floor includes both the old and new protection.
    ///
    /// # Examples
    ///
    /// ```
    /// use qubit_redact::{RedactionFloor, RedactionPolicy, Sensitivity};
    ///
    /// let legacy = RedactionFloor::builder()
    ///     .raise("legacy_pin", Sensitivity::Secret)?
    ///     .build()?;
    /// let provider = RedactionFloor::builder()
    ///     .raise("provider_pin", Sensitivity::Secret)?
    ///     .build()?;
    /// let policy = RedactionPolicy::builder()
    ///     .fields(|fields| { fields.disable_floor(); })?
    ///     .build()?
    ///     .with_floor(legacy);
    /// let combined = policy.rules().clone().add_floor(provider);
    ///
    /// assert_eq!(combined.sensitivity_for("legacy_pin"), Some(Sensitivity::Secret));
    /// assert_eq!(combined.sensitivity_for("provider_pin"), Some(Sensitivity::Secret));
    /// # Ok::<(), qubit_redact::PolicyError>(())
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn add_floor(mut self, floor: RedactionFloor) -> Self {
        self.floor = Some(match self.floor.take() {
            Some(existing) => existing.combine(&floor),
            None => floor,
        });
        self
    }

    /// Disables all floor protection for this rules snapshot.
    ///
    /// # Security
    ///
    /// This explicitly removes global and configured minimum protection. Use it
    /// only when the caller intentionally accepts responsibility for doing so.
    ///
    /// # Returns
    ///
    /// A rules snapshot with no attached floor. Application rules and their
    /// unknown-field policy remain active.
    #[must_use]
    #[inline(always)]
    pub fn disable_floor(mut self) -> Self {
        self.floor = None;
        self
    }

    /// Resolves final sensitivity using exact-only matching in both layers.
    ///
    /// # Parameters
    ///
    /// - `field`: Field name to resolve without token-suffix matching.
    ///
    /// # Returns
    ///
    /// `Some(level)` for the strongest application or floor requirement, or
    /// `None` when both layers permit pass-through.
    #[must_use]
    #[inline(always)]
    pub(crate) fn sensitivity_for_exact(&self, field: &str) -> Option<Sensitivity> {
        match self.resolve_field_exact(field) {
            ResolvedField::Sensitive { sensitivity } => Some(sensitivity),
            ResolvedField::PassThrough => None,
        }
    }

    /// Resolves exact-only sensitivity from application and floor rules.
    ///
    /// # Parameters
    ///
    /// - `field`: Field name to resolve without token-suffix matching.
    ///
    /// # Returns
    ///
    /// The strongest layer decision, or pass-through when neither requires
    /// redaction.
    #[must_use]
    pub(crate) fn resolve_field_exact(&self, field: &str) -> ResolvedField {
        let application = sensitivity_inner(&self.application, field, FieldNameMatching::Exact, true);
        let floor = self.floor.as_ref().and_then(|floor| {
            floor
                .layers
                .iter()
                .filter_map(|layer| sensitivity_inner(layer, field, FieldNameMatching::Exact, false))
                .max()
        });
        resolved_max(application, floor)
    }

    /// Resolves final sensitivity for `field` exactly once.
    ///
    /// # Parameters
    ///
    /// - `field`: Field name resolved using each layer's matching mode.
    ///
    /// # Returns
    ///
    /// The strongest layer decision, or pass-through when neither requires
    /// redaction.
    #[must_use]
    #[inline(always)]
    pub(crate) fn resolve_field(&self, field: &str) -> ResolvedField {
        self.resolve_field_with_matching(field, self.application.matching)
    }

    /// Clones only the application-rule layer for builder reconstruction.
    ///
    /// # Returns
    ///
    /// An independent copy of the application rules, excluding floor
    /// protection.
    #[must_use]
    #[inline(always)]
    pub(crate) fn clone_application(&self) -> RedactionPolicyInner {
        (*self.application).clone()
    }

    /// Resolves final sensitivity using `matching` for application rules.
    ///
    /// # Parameters
    ///
    /// - `field`: Field name to resolve against application and floor rules.
    /// - `matching`: Application candidate matching mode; floor layers retain
    ///   their own matching modes.
    ///
    /// # Returns
    ///
    /// The strongest layer decision, or pass-through when neither requires
    /// redaction.
    #[must_use]
    fn resolve_field_with_matching(&self, field: &str, matching: FieldNameMatching) -> ResolvedField {
        let application = sensitivity_inner(&self.application, field, matching, true);
        let floor = self.floor.as_ref().and_then(|floor| {
            floor
                .layers
                .iter()
                .filter_map(|layer| sensitivity_inner(layer, field, layer.matching, false))
                .max()
        });
        resolved_max(application, floor)
    }
}

/// Combines the application and floor sensitivities, retaining the stronger
/// requirement from either source.
///
/// A `None` input means that source has no sensitivity requirement; it cannot
/// cancel a requirement from the other source. The result is
/// [`ResolvedField::PassThrough`] only when both inputs are `None`.
///
/// # Parameters
///
/// * `application` - Sensitivity resolved from the application rules.
/// * `floor` - Sensitivity resolved from the floor layers.
///
/// # Returns
///
/// The stronger present sensitivity, or [`ResolvedField::PassThrough`] when
/// neither source requires redaction.
#[must_use]
#[inline]
fn resolved_max(application: Option<Sensitivity>, floor: Option<Sensitivity>) -> ResolvedField {
    match application.into_iter().chain(floor).max() {
        Some(sensitivity) => ResolvedField::Sensitive { sensitivity },
        None => ResolvedField::PassThrough,
    }
}

/// Classifies one field against a single rule layer.
///
/// # Type Parameters
///
/// - `'a`: Lifetime of canonical rule names borrowed from `inner`.
///
/// # Parameters
///
/// - `inner`: Rule layer whose canonical names are borrowed by the result.
/// - `field`: Field name to classify.
/// - `matching`: Whether token-suffix candidates are also considered.
/// - `allow`: Whether allow rules may stop classification.
///
/// # Returns
///
/// The first matching allow or sensitive rule, or `Unknown` when no rule
/// matches.
#[must_use]
fn classify_inner<'a>(
    inner: &'a RedactionPolicyInner,
    field: &str,
    matching: FieldNameMatching,
    allow: bool,
) -> FieldClassification<'a> {
    match visit_canonical_field_candidates(field, matching, |is_exact, candidate| {
        let match_kind = if is_exact {
            FieldMatchKind::Exact
        } else {
            FieldMatchKind::TokenSuffix
        };
        if allow
            && is_exact
            && let Some(field) = inner.allow_exact.get(candidate)
        {
            return ControlFlow::Break(FieldClassification::Allowed {
                rule: AllowRule::new(field, FieldNameMatching::Exact),
                match_kind,
            });
        }
        if allow && let Some(field) = inner.allow_suffix.get(candidate) {
            return ControlFlow::Break(FieldClassification::Allowed {
                rule: AllowRule::new(field, FieldNameMatching::ExactOrTokenSuffix),
                match_kind,
            });
        }
        if let Some((field, sensitivity)) = inner.sensitive.get_key_value(candidate) {
            return ControlFlow::Break(FieldClassification::Sensitive {
                rule: SensitiveFieldRule::new(field, *sensitivity),
                match_kind,
            });
        }
        ControlFlow::Continue(())
    }) {
        ControlFlow::Break(classification) => classification,
        ControlFlow::Continue(()) => FieldClassification::Unknown,
    }
}

/// Resolves the strongest sensitivity applicable to one field name in a rule
/// layer.
///
/// Candidate names are visited from the complete canonical field name to
/// progressively shorter semantic token suffixes when `matching` permits
/// suffix matching. Before any sensitive candidate has matched, an applicable
/// allow rule can stop the search and return `None`. Once a sensitive rule has
/// matched, later allow rules do not cancel it; the search continues and
/// returns the strongest sensitivity among the matching sensitive candidates.
/// If neither an allow rule nor any sensitive rule matches, the layer's
/// unknown-field fallback is returned. That fallback does not apply after an
/// allow rule stops the search.
///
/// Unlike [`classify_inner`], this function combines all matching sensitive
/// candidates instead of returning the first classification. Callers resolve
/// separate layers and combine their sensitivities outside this function.
///
/// # Parameters
///
/// * `inner` - The rule layer to inspect.
/// * `field` - The field name being resolved.
/// * `matching` - Controls whether semantic token suffix candidates are
///   considered in addition to the complete canonical name.
/// * `allow` - Whether allow rules in this layer are considered. Floor
///   resolution passes `false` because application allow rules cannot suppress
///   floor requirements.
///
/// # Returns
///
/// The strongest matching sensitivity, the layer's unknown-field fallback
/// when no rule matches, or `None` when an applicable allow rule stops the
/// search or the layer has no sensitivity requirement.
#[must_use]
fn sensitivity_inner(
    inner: &RedactionPolicyInner,
    field: &str,
    matching: FieldNameMatching,
    allow: bool,
) -> Option<Sensitivity> {
    let mut first_match_seen = false;
    let mut strongest: Option<Sensitivity> = None;
    match visit_canonical_field_candidates(field, matching, |is_exact, candidate| {
        if !first_match_seen && allow && is_exact && inner.allow_exact.contains(candidate) {
            return ControlFlow::Break(());
        }
        if !first_match_seen && allow && inner.allow_suffix.contains(candidate) {
            return ControlFlow::Break(());
        }
        if let Some(level) = inner.sensitive.get(candidate) {
            first_match_seen = true;
            strongest = Some(strongest.map_or(*level, |current| current.max(*level)));
        }
        ControlFlow::<()>::Continue(())
    }) {
        ControlFlow::Break(()) => None,
        ControlFlow::Continue(()) => strongest.or_else(|| {
            if first_match_seen {
                None
            } else {
                inner.unknown_field_policy.sensitivity()
            }
        }),
    }
}
