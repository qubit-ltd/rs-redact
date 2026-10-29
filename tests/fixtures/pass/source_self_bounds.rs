// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::Redact;

trait Marker {}
trait HasAssoc {
    type Assoc;
    const SIZE: usize;
}
trait Uses<T> {}
trait RefMarker {}

impl<T> RefMarker for &T {}

#[derive(Redact)]
#[redact(crate = qubit_redact)]
struct Record
where
    Self: Marker,
{
    value: u8,
}

impl Marker for Record {}

#[derive(Redact)]
#[redact(crate = qubit_redact)]
enum GenericEvent<'a, T, const N: usize>
where
    Self: Uses<Self>,
    <Self as HasAssoc>::Assoc: Clone,
    for<'b> &'b Self: RefMarker,
{
    Item { value: &'a T, bytes: [u8; N] },
}

impl<'a, T, const N: usize> HasAssoc for GenericEvent<'a, T, N> {
    type Assoc = u8;
    const SIZE: usize = N;
}

impl<'a, T, const N: usize> Uses<GenericEvent<'a, T, N>> for GenericEvent<'a, T, N> {}

fn main() {
    let _ = Record { value: 7 };
    let value = 3u8;
    let event: GenericEvent<'_, u8, 2> = GenericEvent::Item {
        value: &value,
        bytes: [1, 2],
    };
    let _ = event;
}
