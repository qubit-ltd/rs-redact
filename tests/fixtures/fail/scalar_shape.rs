// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use qubit_redact::RedactScalar;

#[derive(RedactScalar)]
struct Empty;

#[derive(RedactScalar)]
struct Pair(u64, u64);

#[derive(RedactScalar)]
enum Choice {
    Item(u64),
}

#[derive(RedactScalar)]
struct Classified(#[redact(level = "secret")] String);

fn main() {}
