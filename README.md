# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

`qubit-redact` produces bounded, log-safe diagnostic text from fields, Rust
domain values, command data, JSON, HTTP, and URIs. It is for applications that
need one coherent redaction decision for a whole event, rather than a separate
policy, budget, and publication point for every value they log.

## Installation

Choose only the format integrations your application uses:

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http", "json", "uri"] }
```

The minimum supported Rust version is 1.94. `serde`, `json`, `http`, and `uri`
are optional features. Field, domain, argv, environment, and process redaction
are available with the default feature set.

## Quick Start

An API client wants one failure message and a separately retained URL for
telemetry. The access token must never be published, and both values must use
the same limits. Build the immutable policy once, then let one session own the
event:

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

`finish()` is the publication boundary: it returns aggregate text, the
transaction summary, and the item results. An opaque `RedactionHandle` can be
resolved only with the `RedactionSessionOutput` that created it. The session is
then ready for the next event with the same policy snapshot.

## Why This Project Exists

Independent formatting helpers are easy to compose but easy to get wrong: a
URL and a response body can use different rules, each can consume an unrelated
output allowance, and partially rendered data can escape before a callback
fails. `RedactionSession` keeps an event private while it is being assembled.
All aggregate and item operations share one policy and transaction budget;
`finish()` publishes the completed result atomically. If user redaction code
panics, the active transaction is discarded and unwinding continues.

## What It Provides

- Immutable `RedactionPolicy` snapshots, including deterministic `standard()`
  and fail-closed `strict()` policies.
- Transactional configuration of field rules, masking, limits, and enabled
  HTTP/URI/JSON behavior.
- Aggregate text APIs and separately resolved item APIs for argv, environment,
  process, JSON, HTTP, and URI data.
- Explicit domain rendering through `Redact` and `RedactionWriter`.
- Machine-readable completion, reasons, and usage in `RedactionSummary`.
- UTF-8, log-safe output that safely degrades when an input, output, or
  structural limit is reached.

The crate does not discover secrets from arbitrary value contents. Review each
business field and mark it deliberately. `unredacted` is an explicit trust
boundary, not a convenience escape hatch; it must receive only independently
reviewed safe data. Limits apply to the complete diagnostic event, not to each
format in isolation.

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
