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
- Malformed or truncated structured HTTP input fails closed, and finite budgets
  bound inspection, output, JSON recursion, and disclosure.
- The default feature set is empty; the core crate has no external runtime
  dependencies.

## Quick Start

```toml
[dependencies]
qubit-redact = "0.5"
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

    assert_eq!(redactor.redact_field("user_id", "alpine42").as_str(), "al****42");
    assert_eq!(redactor.redact_field("phone_number", "13800138000").as_str(), "*******0");
    assert_eq!(redactor.redact_field("credit_card", "4111111111111111").as_str(), "****");
    assert_eq!(redactor.redact_field("api_key", "sk_live_123").as_str(), "<redacted>");

    let safe = redactor
        .redact_field("display_name", "Alice\nAdmin")
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
| Named scalar value | `Redactor::redact_field` | `RedactedText`; call `escape_for_log()` for plain-text logs. |
| Text-keyed map | `Redactor::redact_map` or `redact_map_in_place` | A copied or mutated map; apply the final logging format yourself. |
| Rust struct or enum | `Redact` derive | Borrowed `Redacted<T>` view with safe formatting. |
| Value that must be logically replaced | `RedactMut` derive | Mutated value; this is not memory erasure. |
| Command arguments | `ArgvRedactor` | `RedactedArgv`, safe to display. |
| Environment pairs | `EnvRedactor` | `RedactedEnvPair` or `LogSafeText`. |
| URL, form, headers, or captured body | `HttpRedactor` | Bounded, log-safe HTTP result types. |

## Cargo Features

| Need | Cargo configuration |
| --- | --- |
| Core scalar, map, process, and text support | `qubit-redact = "0.5"` |
| Domain-object derives | Add `qubit-redact-derive = "0.5"`. |
| Serialize redacted views | Enable `serde` and declare `serde` directly. |
| Redact `serde_json::Value` or JSON text fields | Enable `json`; add `serde_json` directly when your application uses it. |
| HTTP diagnostics | Enable `http`; add `http` directly when your application uses its types. |

```toml
[dependencies]
# HTTP diagnostics only
qubit-redact = { version = "0.5", features = ["http"] }
http = "1.4"
```

## Safety Boundaries

- Unknown field names pass through by default. Set
  `UnknownFieldPolicy::Redact(Sensitivity::Secret)` when a boundary must mask
  every unclassified field; `classify_field()` still reports `Unknown`.
  `RedactionPolicy::strict()` provides this boundary preset without changing
  the default policy semantics.
- Application allow rules never bypass an enabled `RedactionFloor`. Use
  `RedactionPolicy::builder()` for empty application rules with the standard
  floor, and use `RedactionPolicy::default().to_builder()` for the normal
  "extend defaults" path. `disable_floor()` intentionally removes every
  floor and is appropriate only when the caller owns that security decision.
- Install one `GlobalRedactionConfig` during application assembly. It affects
  only future snapshots; already-built policies and redactors never change.
- `redact_field()` returns `FieldRedaction`, which distinguishes masked values
  from allowed and unknown pass-through values.
- `RedactedText` is not displayable by design. Redaction and log escaping are
  separate guarantees.
- Use `with_policy_output_limit()` when a redacted domain or map view must be
  bounded by the policy diagnostic budget; its `Debug` and `Display` output is
  both bounded and log-safe.
- `RedactMut` replaces logical values only. It does not erase released
  allocations, aliases, copies, or borrowed backing storage.
- JSON redaction stops at `JsonDepthBudget` and replaces an over-depth subtree
  with the policy's opaque Secret mask. The default maximum depth is 128.
- HTTP redaction accepts only caller-provided captures. It never reads or
  buffers a network body itself. Import `HttpRedactionPolicy` from
  `qubit_redact::http`, not from an HTTP client crate.

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
