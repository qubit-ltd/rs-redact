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
- One immutable `RedactionPolicy` owns base fields, HTTP/URI context overrides,
  masking, and static limits. Nested diagnostic values reuse one
  `RedactionSession`, so a child cannot reset the parent's budget.
- URI redaction preserves raw scheme, authority, path, query order, and
  encoding while applying the core policy independently to username/password,
  query values, and configurable path/fragment boundaries.
- The default feature set is empty; the core crate has no external runtime
  dependencies.

## Quick Start

```toml
[dependencies]
qubit-redact = "0.4"
```

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = RedactionPolicy::builder();
    builder.fields().raise("user_id", Sensitivity::Low)?;
    builder.fields().raise("phone_number", Sensitivity::Medium)?;
    builder.fields().raise("credit_card", Sensitivity::High)?;
    builder.fields().raise("api_key", Sensitivity::Secret)?;
    let policy = builder.build()?;
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

Install a process-wide default during application assembly:

```rust
use qubit_redact::{RedactionPolicy, Sensitivity};

let mut builder = RedactionPolicy::builder();
builder.fields().raise("api_key", Sensitivity::Secret)?;
let policy = builder.build()?;
RedactionPolicy::install_global(policy)?;
let snapshot = RedactionPolicy::default();
# Ok::<(), Box<dyn std::error::Error>>(())
```

If no policy is installed, global/default reads use the fixed standard policy.
They do not prevent a later `install_global()` call. Existing snapshots never
change when a policy is installed later.

> **Warning:** `install_global()` belongs only in executable application
> assembly. Call it once after the final policy is built and before workers or
> request processing start; libraries must never call it. Objects created
> before installation may snapshot the standard policy permanently. Create any
> object that requires the application policy after installation, or inject the
> policy explicitly. The fallback supports initialization ordering and is not
> runtime reconfiguration.

## Derive Support

`qubit-redact-derive` provides procedural macros for applying redaction policies
to Rust structs and enums. `Redact` creates a borrowed `Redacted<T>` view for
diagnostics, while `RedactMut` performs an explicit logical replacement when an
owned value is required. Use it with the `qubit-redact` runtime crate; the
complete field attributes and Serde/JSON integration are covered in the
[derive README](https://github.com/qubit-ltd/rs-redact-derive/blob/main/README.md) and [derive User Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md).

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
| URI string | `UriRedactor` (`uri` feature) | Structured, log-safe result with component reasons. |

## Cargo Features

| Need | Cargo configuration |
| --- | --- |
| Core scalar, map, process, and text support | `qubit-redact = "0.4"` |
| Domain-object derives | Add `qubit-redact-derive = "0.4"`. |
| Serialize redacted views | Enable `serde` and declare `serde` directly. |
| Redact `serde_json::Value` or JSON text fields | Enable `json`; add `serde_json` directly when your application uses it. |
| HTTP diagnostics | Enable `http`; add `http` directly when your application uses its types. |
| Policy-driven URI redaction | Enable `uri`; this is independent from `http`. |

The derive `#[redact(json)]` mode keeps JSON text fields as their outer Rust
`String` type. When combined with `#[redact(serde)]`, the redacted value is
still serialized as a JSON string.

```toml
[dependencies]
# HTTP diagnostics only
qubit-redact = { version = "0.4", features = ["http"] }
http = "1.5"

# URI diagnostics without the HTTP feature
# qubit-redact = { version = "0.4", features = ["uri"] }
```

## Safety Boundaries

- Unknown field names pass through by default. Set
  `UnknownFieldPolicy::Redact(Sensitivity::Secret)` when a boundary must mask
  every unclassified field; `classify_field()` still reports `Unknown`.
  `RedactionPolicy::strict()` provides this boundary preset without changing
  the default policy semantics.
- Application allow rules never bypass an enabled `RedactionFloor`. Use
  `RedactionPolicy::builder()` for empty application rules with the standard
  floor; this builder is deterministic and never reads global state. Use
  `RedactionPolicy::default().to_builder()` for the normal "extend defaults"
  path. `disable_floor()` intentionally removes every floor and is appropriate
  only when the caller owns that security decision.
- Configure all concerns through one `RedactionPolicyBuilder`: use
  `fields()`, `http()`, `uri()`, and `limits()` as mutable partition views.
  Context rules can add protection but cannot lower a stronger base-field
  decision. The policy has one masking table and one limit set.
- Install one global policy with `RedactionPolicy::install_global()` during
  application assembly. It affects only future snapshots; already-built
  policies and redactors never change. Before installation, `global()` and
  `default()` use the fixed standard policy without occupying the install slot.
- `Debug` for redacted domain/map views uses the policy's
  `limits().diagnostic_event()` output budget by default. Derived nested values,
  maps, JSON text, and explicit adapter sessions share the same
  `RedactionSession`; a child cannot obtain a fresh budget silently.
- `InputOutputLimit` is the immutable policy setting; `RedactionSession` is the
  non-cloneable runtime accounting object used for one operation or diagnostic
  event. Reuse one session across adapters. Output accounting is committed by
  those adapters so fallback markers cannot bypass the cumulative limit.
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
  buffers a network body itself. Configure HTTP behavior on the root
  `RedactionPolicy`; `HttpRedactor` consumes that snapshot.
- URI redaction is opt-in through `qubit_redact::uri::UriRedactor`. Userinfo is
  split only at the first raw `:`; username uses the `username` field rule and
  password uses `password`. Query keys are decoded strictly for classification,
  while unmasked values retain their original percent-encoded spelling. Invalid
  URI syntax or undecodable query components return a fixed marker.

## Learn More

- [English User Guide](doc/user_guide.md) and [中文用户手册](doc/user_guide.zh_CN.md)
- [Runtime API documentation](https://docs.rs/qubit-redact)
- [qubit-redact-derive README](https://github.com/qubit-ltd/rs-redact-derive/blob/main/README.md) for field attributes and serde support
- [qubit-redact-derive User Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md)
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
