# Qubit Redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

Qubit Redact prevents sensitive values from leaking through Rust diagnostics:
logs, `Debug` output, process arguments, environment variables, and optional
HTTP traces. Define immutable policies once, then render typed results at an
explicit log-safe boundary.

## Why Qubit Redact

- One policy model classifies named fields across scalar values, maps, domain
  objects, process diagnostics, and optional HTTP data.
- Typed results distinguish redacted values from text that is safe to write to
  a plain-text log.
- Malformed or truncated structured HTTP input fails closed, and diagnostic
  budgets bound inspection, output, and disclosure.
- The default feature set is empty; the core crate has no external runtime
  dependencies.

## Quick Start

```toml
[dependencies]
qubit-redact = "0.3"
```

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .raise("user_id", Sensitivity::Low)
        .raise("phone_number", Sensitivity::Medium)
        .raise("credit_card", Sensitivity::High)
        .raise("api_key", Sensitivity::Secret)
        .build()?;
    let redactor = Redactor::new(policy);

    assert_eq!(redactor.redact("user_id", "alpine42").as_str(), "al****42");
    assert_eq!(redactor.redact("phone_number", "13800138000").as_str(), "*******0");
    assert_eq!(redactor.redact("credit_card", "4111111111111111").as_str(), "****");
    assert_eq!(redactor.redact("api_key", "sk_live_123").as_str(), "<redacted>");

    let safe = redactor
        .redact("display_name", "Alice\nAdmin")
        .escape_for_log();
    assert_eq!(safe.to_string(), "Alice\\nAdmin");
    Ok(())
}
```

The original value remains available to application logic. Call
`escape_for_log()` before writing a scalar result to a plain-text log sink.

## Choose a Tool

| Diagnostic input | Tool | Result and logging boundary |
| --- | --- | --- |
| Named scalar value | `Redactor::redact` | `RedactedText`; call `escape_for_log()` for plain-text logs. |
| Text-keyed map | `Redactor::redact_map` or `redact_map_in_place` | A copied or mutated map; apply the final logging format yourself. |
| Rust struct or enum | `Redact` derive | Borrowed `Redacted<T>` view with safe formatting. |
| Value that must be logically replaced | `RedactMut` derive | Mutated value; this is not memory erasure. |
| Command arguments | `ArgvRedactor` | `RedactedArgv`, safe to display. |
| Environment pairs | `EnvRedactor` | `RedactedEnvPair` or `LogSafeText`. |
| URL, form, headers, or captured body | `HttpRedactor` | Bounded, log-safe HTTP result types. |

## Cargo Features

| Need | Cargo configuration |
| --- | --- |
| Core scalar, map, process, and text support | `qubit-redact = "0.3"` |
| Domain-object derives | Add `qubit-redact-derive = "0.3"`. |
| Serialize redacted views | Enable `serde` and declare `serde` directly. |
| HTTP diagnostics | Enable `http`; add `http` directly when your application uses its types. |

```toml
[dependencies]
# HTTP diagnostics only
qubit-redact = { version = "0.3", features = ["http"] }
http = "1.4"
```

## Safety Boundaries

- Unknown field names pass through unchanged. This crate is not a general
  secret detector; configure every field name your application controls.
- Allow rules intentionally win and can disclose data. Prefer exact allow rules
  and treat each one as a security decision.
- `RedactedText` is not displayable by design. Redaction and log escaping are
  separate guarantees.
- `RedactMut` replaces logical values only. It does not erase released
  allocations, aliases, copies, or borrowed backing storage.
- HTTP redaction accepts only caller-provided captures. It never reads or
  buffers a network body itself.

## Learn More

- [English User Guide](doc/user_guide.md) and [中文用户手册](doc/user_guide.zh_CN.md)
- [Runtime API documentation](https://docs.rs/qubit-redact)
- [Derive crate README](derive/README.md) for field attributes and serde support
- [Derive crate API documentation](https://docs.rs/qubit-redact-derive)

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
