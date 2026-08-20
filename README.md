# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

`qubit-redact` builds bounded, log-safe diagnostics without letting each field
or format silently create its own policy, budget, or publication boundary. It
is intended for Rust applications that compose scalar fields, domain objects,
command data, JSON, HTTP, and URIs into one diagnostic event.

## Installation

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http", "json", "uri"] }
```

The crate requires Rust 1.94 or later. The `serde`, `json`, `http`, and `uri`
features enable their corresponding integrations; argv, env, process, fields,
and domain writers are available without optional features.

## Quick Start

Suppose an HTTP client failure must log a request identifier and a redacted URL
while also returning the URL separately to structured telemetry. One reusable
session keeps both results under one transaction-wide resource limit and does
not publish either handle item until `finish()`:

```rust
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

let policy = RedactionPolicy::builder()
    .fields(|fields| {
        fields.secret_sensitive("access_token");
    })?
    .limits(|limits| {
        limits.max_input_bytes(64 * 1024).max_output_bytes(16 * 1024);
    })?
    .build()?;

let mut session = Redactor::new(policy).session();
let url = session.redact_http_url(
    "https://api.example.test/users?access_token=raw-secret",
);
session.literal("request failed: ").field("request_id", "req-42");

let output = session.finish();
let safe_url = output.resolve(url)?;
assert!(!output.text().as_str().contains("raw-secret"));
assert!(!safe_url.text().as_str().contains("raw-secret"));

# Ok::<(), Box<dyn std::error::Error>>(())
```

The same session can immediately start another transaction. A handle resolves
only against the `RedactionSessionOutput` from the transaction that created it.

## Why This Project Exists

Logging helpers often redact each value independently. That makes policy
snapshots inconsistent, lets combined output exceed its intended bound, and
can expose partially built text before all user callbacks finish. Here,
`RedactionSession` owns one private transaction. `finish()` atomically publishes
aggregate text, item results, and a machine-readable `RedactionSummary`, then
resets the session for reuse. A panic in user redaction code discards the whole
active transaction and continues unwinding.

## What It Provides

- Deterministic `standard()` and `strict()` policies plus an atomic
  application-default snapshot for `Redact::redacted()`.
- Transactional policy namespaces for field rules, resource limits, HTTP, and
  URI configuration.
- Aggregate APIs and opaque handle APIs for argv, env, process, JSON, HTTP, and
  URI data, all sharing the transaction runtime.
- Explicit domain writing through `Redact` and `RedactionWriter`, with
  completion, reason, and usage accounting.
- Bounded UTF-8 and log-safe output. Budget exhaustion and invalid formats
  fail closed and are reported in the summary instead of aborting `finish()`.

This crate does not infer sensitivity from arbitrary value contents. Every
newly added business field must be reviewed. `RedactionWriter::unredacted` is
an explicit trust boundary and must never receive secrets. For dynamic maps,
`RedactionFields::map` classifies each entry by its own key through the active
policy.

## Migration from the Pre-Transaction API

| Removed concept | Transactional replacement |
| --- | --- |
| `RedactionConfig` and mutable edit views | `RedactionPolicy::builder()` namespaces |
| Per-format redactor facades | `Redactor::redact_*` or `RedactionSession` format APIs |
| Lazy/display result wrappers | `RedactionOutput` after `finish()` |
| Keyed session results | Opaque `RedactionHandle` plus `output.resolve(handle)` |
| Session errors for safe degradation | `RedactionSummary` completion, reasons, and usage |

No deprecated aliases or compatibility modules are provided.

## Learn More

- [English user guide](doc/user_guide.md)
- [中文用户指南](doc/user_guide.zh_CN.md)
- [API documentation](https://docs.rs/qubit-redact)
- [Transactional architecture](doc/2026-08-19-rs-redact-transactional-redesign-design.md)

## Testing

```bash
# Run tests with the default feature set
cargo test

# Run tests with all declared features
cargo test --all-features

# Project CI checks
./ci-check.sh

# Check code coverage
./coverage.sh
```

## License

Copyright (c) 2025 - 2026. Haixing Hu. All rights reserved.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full license text.

## Contributing

Contributions are welcome. Please follow the Rust API guidelines, keep public
API documentation and tests current, and run `./align-ci.sh` to format code and
`./ci-check.sh` to satisfy CI requirements before submitting a pull request.

## Author

**Haixing Hu** - *Qubit Co. Ltd.*

Repository: [https://github.com/qubit-ltd/rs-redact](https://github.com/qubit-ltd/rs-redact)
