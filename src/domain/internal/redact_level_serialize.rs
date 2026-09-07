// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured serialization for values with an explicit sensitivity.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::LinkedList;
use std::collections::VecDeque;
use std::fmt;
use std::fmt::Display;
use std::hash::Hash;
use std::rc::Rc;
use std::sync::Arc;

#[cfg(feature = "bigdecimal")]
use bigdecimal::BigDecimal;
use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as SerdeError;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;
use serde::ser::SerializeTuple;

use super::bounded_display_writer::BoundedDisplayWriter;
use super::budget_serialize::BudgetSerialize;
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::admit_input;
use super::redact_serialize_scope::admit_payload;
use super::redact_serialize_scope::remaining_input_bytes;
use super::redacted_level_serialize_ref::RedactedLevelSerializeRef;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Internal structured serialization capability for scalar level fields.
#[doc(hidden)]
pub trait RedactLevelSerialize {
    /// Serializes this value at the explicitly declared sensitivity.
    ///
    /// # Errors
    ///
    /// Propagates payload admission or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

/// Generates primitive level adapters with bounded formatting and payload
/// admission.
macro_rules! scalar_level_serialize {
    ($($type:ty),+ $(,)?) => {
        $(impl RedactLevelSerialize for $type {
            /// Applies the explicit level while sharing input, payload, and structural admission.
            ///
            /// # Errors
            ///
            /// Propagates bounded payload or downstream serialization failures.
            ///
            /// # Type Parameters
            ///
            /// - `S`: Downstream serializer defining the success and error types.
            ///
            /// # Parameters
            ///
            /// - `serializer`: Destination receiving the admitted representation.
            /// - `policy`: Immutable policy controlling redaction and resource limits.
            /// - `level`: Explicit sensitivity applied to scalar leaves.
            ///
            /// # Returns
            ///
            /// The destination result after all emitted data passes shared admission.
            fn serialize_redacted_level<S>(
                &self,
                serializer: S,
                policy: &RedactionPolicy,
                level: Sensitivity,
            ) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if policy.is_disabled() {
                    serialize_disabled_display(self, serializer, policy)
                } else {
                    serialize_masked_display(self, serializer, policy, level)
                }
            }
        })+
    };
}

/// Serializes an admitted display value using the configured level mask.
///
/// # Errors
///
/// Returns a serializer error when the masked payload exceeds its allowance
/// or the downstream serializer rejects it.
///
/// # Type Parameters
///
/// - `S`: Destination serializer.
/// - `T`: Possibly unsized source implementing `Display`.
///
/// # Parameters
///
/// - `value`: Source formatted only for levels requiring its text.
/// - `serializer`: Destination receiving the selected mask.
/// - `policy`: Immutable mask and resource policy.
/// - `level`: Explicit sensitivity for this scalar.
fn serialize_masked_display<S, T>(
    value: &T,
    serializer: S,
    policy: &RedactionPolicy,
    level: Sensitivity,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Display + ?Sized,
{
    if matches!(level, Sensitivity::High | Sensitivity::Secret) {
        return super::redact_serialize_scope::serialize_payload(serializer, policy.masking().mask_opaque(level));
    }
    let Some(raw) = format_admitted_display(value) else {
        return super::redact_serialize_scope::serialize_payload(
            serializer,
            policy.masking().mask_opaque(Sensitivity::Secret),
        );
    };
    let (masked, truncated) = policy.masking().mask_bounded_with_truncation(
        level,
        &raw,
        super::redact_serialize_scope::remaining_payload_bytes(),
    );
    if truncated {
        return Err(SerdeError::custom("redaction scalar payload budget exceeded"));
    }
    super::redact_serialize_scope::serialize_payload(serializer, masked.as_ref())
}

/// Serializes a raw disabled-mode scalar only after bounded input admission.
///
/// Values that exceed the remaining allowance serialize as the stable secret
/// opaque mask instead of invoking their ordinary serializer.
///
/// # Errors
///
/// Returns a payload admission error or propagates the value serializer error.
///
/// # Type Parameters
///
/// - `S`: Destination serializer.
/// - `T`: Possibly unsized source implementing `Display` and `Serialize`.
///
/// # Parameters
///
/// - `value`: Source whose formatted size is admitted before ordinary
///   serialization.
/// - `serializer`: Destination receiving the original representation or safe
///   fallback.
/// - `policy`: Immutable resource and fallback-mask policy.
fn serialize_disabled_display<S, T>(value: &T, serializer: S, policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Display + Serialize + ?Sized,
{
    let Some(raw) = format_admitted_display(value) else {
        return super::redact_serialize_scope::serialize_payload(
            serializer,
            policy.masking().mask_opaque(Sensitivity::Secret),
        );
    };
    if !admit_payload(raw.len()) {
        return Err(SerdeError::custom("redaction scalar payload budget exceeded"));
    }
    Serialize::serialize(value, serializer)
}

/// Formats and charges one scalar without allocating past the remaining input
/// allowance.
///
/// Returns the complete formatted value after charging it, or `None` when
/// formatting fails or the value exceeds the cumulative allowance.
///
/// # Type Parameters
///
/// - `T`: Possibly unsized source implementing `Display`.
///
/// # Parameters
///
/// - `value`: Source formatted once under the remaining input allowance.
///
/// # Returns
///
/// Some complete admitted text; None on formatter failure, capture rejection,
/// or cumulative input exhaustion.
#[must_use]
fn format_admitted_display<T>(value: &T) -> Option<String>
where
    T: Display + ?Sized,
{
    let mut writer = BoundedDisplayWriter::new(remaining_input_bytes());
    if fmt::write(&mut writer, format_args!("{value}")).is_err() {
        return None;
    }
    let raw = writer.finish()?;
    if !admit_input(raw.len()) {
        return None;
    }
    Some(raw)
}

scalar_level_serialize!(
    String, str, char, bool, i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize, f32, f64
);

#[cfg(feature = "bigdecimal")]
impl RedactLevelSerialize for BigDecimal {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if policy.is_disabled() {
            serialize_disabled_display(self, serializer, policy)
        } else {
            serialize_masked_display(self, serializer, policy, level)
        }
    }
}

impl<'a> RedactLevelSerialize for Cow<'a, str> {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if policy.is_disabled() {
            serialize_disabled_display(self, serializer, policy)
        } else {
            serialize_masked_display(self, serializer, policy, level)
        }
    }
}

impl<T: RedactLevelSerialize + ?Sized> RedactLevelSerialize for &T {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    #[inline(always)]
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (*self).serialize_redacted_level(serializer, policy, level)
    }
}

impl<T: RedactLevelSerialize> RedactLevelSerialize for Option<T> {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Some(value) => value.serialize_redacted_level(serializer, policy, level),
            None => serializer.serialize_none(),
        }
    }
}

impl<T: RedactLevelSerialize> RedactLevelSerialize for Vec<T> {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !admit_collection_items(self.len()) {
            return super::redact_serialize_scope::serialize_payload(
                serializer,
                policy.masking().mask_opaque(Sensitivity::Secret),
            );
        }
        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for value in self {
            sequence.serialize_element(&RedactedLevelSerializeRef::new(value, policy, level))?;
        }
        sequence.end()
    }
}

/// Generates cumulative collection admission for standard sequence-like types.
macro_rules! sequence_level_serialize {
    ($($type:ident),+ $(,)?) => {
        $(impl<T: RedactLevelSerialize> RedactLevelSerialize for $type<T> {
            /// Applies the explicit level while sharing input, payload, and structural admission.
            ///
            /// # Errors
            ///
            /// Propagates bounded payload or downstream serialization failures.
            ///
            /// # Type Parameters
            ///
            /// - `S`: Downstream serializer defining the success and error types.
            ///
            /// # Parameters
            ///
            /// - `serializer`: Destination receiving the admitted representation.
            /// - `policy`: Immutable policy controlling redaction and resource limits.
            /// - `level`: Explicit sensitivity applied to scalar leaves.
            ///
            /// # Returns
            ///
            /// The destination result after all emitted data passes shared admission.
            fn serialize_redacted_level<S>(&self, serializer: S, policy: &RedactionPolicy, level: Sensitivity) -> Result<S::Ok, S::Error>
            where S: Serializer {
                if !admit_collection_items(self.len()) {
                    return super::redact_serialize_scope::serialize_payload(serializer, policy.masking().mask_opaque(Sensitivity::Secret).as_ref());
                }
                let mut sequence = serializer.serialize_seq(Some(self.len()))?;
                for value in self {
                    sequence.serialize_element(&RedactedLevelSerializeRef::new(value, policy, level))?;
                }
                sequence.end()
            }
        })+
    };
}

sequence_level_serialize!(VecDeque, LinkedList, BinaryHeap, BTreeSet, HashSet);

impl<T: RedactLevelSerialize + ?Sized> RedactLevelSerialize for Box<T> {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    #[inline(always)]
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (**self).serialize_redacted_level(serializer, policy, level)
    }
}
impl<T: RedactLevelSerialize + ?Sized> RedactLevelSerialize for Rc<T> {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    #[inline(always)]
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (**self).serialize_redacted_level(serializer, policy, level)
    }
}
impl<T: RedactLevelSerialize + ?Sized> RedactLevelSerialize for Arc<T> {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    #[inline(always)]
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (**self).serialize_redacted_level(serializer, policy, level)
    }
}

impl<K: Serialize + Eq + Hash, V: RedactLevelSerialize> RedactLevelSerialize for HashMap<K, V> {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !admit_collection_items(self.len()) {
            return super::redact_serialize_scope::serialize_payload(
                serializer,
                policy.masking().mask_opaque(Sensitivity::Secret),
            );
        }
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (key, value) in self {
            map.serialize_entry(
                &BudgetSerialize::new(key),
                &RedactedLevelSerializeRef::new(value, policy, level),
            )?;
        }
        map.end()
    }
}
impl<K: Serialize + Ord, V: RedactLevelSerialize> RedactLevelSerialize for BTreeMap<K, V> {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !admit_collection_items(self.len()) {
            return super::redact_serialize_scope::serialize_payload(
                serializer,
                policy.masking().mask_opaque(Sensitivity::Secret),
            );
        }
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (key, value) in self {
            map.serialize_entry(
                &BudgetSerialize::new(key),
                &RedactedLevelSerializeRef::new(value, policy, level),
            )?;
        }
        map.end()
    }
}

impl<T: RedactLevelSerialize, const N: usize> RedactLevelSerialize for [T; N] {
    /// Applies the explicit level while sharing input, payload, and structural
    /// admission.
    ///
    /// # Errors
    ///
    /// Propagates bounded payload or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    /// - `policy`: Immutable policy controlling redaction and resource limits.
    /// - `level`: Explicit sensitivity applied to scalar leaves.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !admit_collection_items(N) {
            return super::redact_serialize_scope::serialize_payload(
                serializer,
                policy.masking().mask_opaque(Sensitivity::Secret),
            );
        }
        let mut sequence = serializer.serialize_seq(Some(N))?;
        for value in self {
            sequence.serialize_element(&RedactedLevelSerializeRef::new(value, policy, level))?;
        }
        sequence.end()
    }
}

/// Generates fixed-arity tuple admission and level-aware element adapters.
macro_rules! tuple_level_serialize {
    ($count:expr; $($name:ident => $index:tt),+) => {
        impl<$($name: RedactLevelSerialize),+> RedactLevelSerialize for ($($name,)+) {
            /// Applies the explicit level while sharing input, payload, and structural admission.
            ///
            /// # Errors
            ///
            /// Propagates bounded payload or downstream serialization failures.
            ///
            /// # Type Parameters
            ///
            /// - `S`: Downstream serializer defining the success and error types.
            ///
            /// # Parameters
            ///
            /// - `serializer`: Destination receiving the admitted representation.
            /// - `policy`: Immutable policy controlling redaction and resource limits.
            /// - `level`: Explicit sensitivity applied to scalar leaves.
            ///
            /// # Returns
            ///
            /// The destination result after all emitted data passes shared admission.
            fn serialize_redacted_level<S>(&self, serializer: S, policy: &RedactionPolicy, level: Sensitivity) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if !admit_collection_items($count) {
                    return super::redact_serialize_scope::serialize_payload(serializer,
                        policy
                            .masking()
                            .mask_opaque(Sensitivity::Secret)
                            .as_ref(),
                    );
                }
                let mut tuple = serializer.serialize_tuple($count)?;
                $(tuple.serialize_element(&RedactedLevelSerializeRef::new(&self.$index, policy, level))?;)+
                tuple.end()
            }
        }
    };
}

tuple_level_serialize!(1; A => 0);
tuple_level_serialize!(2; A => 0, B => 1);
tuple_level_serialize!(3; A => 0, B => 1, C => 2);
tuple_level_serialize!(4; A => 0, B => 1, C => 2, D => 3);
tuple_level_serialize!(5; A => 0, B => 1, C => 2, D => 3, E => 4);
tuple_level_serialize!(6; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5);
tuple_level_serialize!(7; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6);
tuple_level_serialize!(8; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7);
tuple_level_serialize!(9; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8);
tuple_level_serialize!(10; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9);
tuple_level_serialize!(11; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10);
tuple_level_serialize!(12; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10, L => 11);

/// Serializes an explicitly textual Display adapter, including disabled output.
///
/// # Errors
///
/// Returns serializer errors or a logical-payload error from admission.
///
/// # Type Parameters
///
/// - `S`: Destination serializer.
/// - `T`: Possibly unsized source implementing `Display`.
///
/// # Parameters
///
/// - `value`: Explicit textual source formatted only when required.
/// - `serializer`: Destination receiving text or the selected mask.
/// - `policy`: Immutable redaction and resource policy.
/// - `level`: Explicit scalar sensitivity when redaction is enabled.
pub(super) fn serialize_display_text<S, T>(
    value: &T,
    serializer: S,
    policy: &RedactionPolicy,
    level: Sensitivity,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Display + ?Sized,
{
    if !policy.is_disabled() {
        return serialize_masked_display(value, serializer, policy, level);
    }
    let raw = format_admitted_display(value);
    let text = raw
        .as_deref()
        .unwrap_or_else(|| policy.masking().mask_opaque(Sensitivity::Secret));
    super::redact_serialize_scope::serialize_payload(serializer, text)
}
