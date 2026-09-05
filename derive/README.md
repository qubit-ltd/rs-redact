# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

`qubit-redact-derive` provides the `#[derive(Redact)]` procedural macro for
[`qubit-redact`](https://crates.io/crates/qubit-redact). It turns reviewed
field annotations into a policy-aware `Redact::write_redacted` implementation.
The derive never mutates the source value and exposes no mutable redaction API.

## Installation

```toml
[dependencies]
qubit-redact = { version = "0.6", features = ["derive"] }
qubit-redact-derive = "0.6"
```

## Quick Start

```rust
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    recovery_code: String,
}

let value = Credentials {
    user: "ada".into(),
    password: "raw-password".into(),
    recovery_code: "never-render".into(),
};
let output = Redactor::standard().redact(&value);
assert!(output.text().as_str().contains("ada"));
assert!(!output.text().as_str().contains("raw-password"));
assert!(!output.text().as_str().contains("never-render"));
```

Unmarked fields intentionally use ordinary `Debug` formatting. Whether a field
is sensitive is downstream business-domain knowledge that a derive macro cannot
reliably infer from its name or Rust type. Because ordinary fields are the vast
majority, requiring an explicit "not sensitive" attribute on every one would
create annotation noise without improving classification. Downstream types must
explicitly annotate sensitive fields and review new or changed fields. The
runtime's strict policy and inspection do not override this derive decision.

## Field modes

| Attribute | Behavior |
| --- | --- |
| no attribute | Render ordinary `Debug` output. |
| `#[redact(level = "low"\|"medium"\|"high"\|"secret")]` | Mask the field at the selected sensitivity. |
| `#[redact(skip)]` | Omit the field from the redacted output. |
| `#[redact(nested)]` | Delegate to the nested value's `Redact` implementation. |
| `#[redact(map)]` | Apply key-aware policy to supported text-keyed maps. |
| `#[redact(keyed_by = key)]` | Classify this field by a sibling text key, using the same policy semantics as one map entry. |
| `#[redact(json)]` | Apply recursive JSON-key redaction to supported JSON text values. |

`#[redact(plain)]`, `#[redact(no_mut)]`, and `#[redact(require_explicit)]` are
not part of the current contract. The macro supports named, tuple, and unit
structs and enum variants. `#[redact(debug)]`, `#[redact(display)]`, and
`#[redact(serde)]` are opt-in container attributes; Serde support requires the
runtime `serde` feature and a direct `serde` dependency. Their generated
implementations intentionally obtain the current
`Redactor::application_default()` snapshot at the start of every formatting or
serialization call; they do not capture policy when the value is created.
Replacing the process-wide default therefore affects subsequent calls.

`keyed_by` is available only on named fields. The referenced sibling key must
implement `AsRef<str>`, while the value uses the same recursive leaf capability
as `level`. Standard policies pass unknown keys through; configure sensitive
keys explicitly or use a stricter policy when unknown payload keys must be
masked.

The generated code resolves a direct `qubit-redact` dependency, including a
Cargo-renamed dependency. The runtime trait is intentionally small:

```rust
pub trait Redact {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);
}
```

## Safety boundary

Redaction protects only the boundary that uses `Redactor`, generated formatting,
or generated serialization. It does not erase the original value and cannot
protect unrelated logs or serialization paths. `skip` omits output but retains
the source field in memory. An unmarked field's pass-through behavior is an
intentional responsibility boundary, not a missing framework check.

Generated `Debug` and `Display` implementations write the confidentiality-safe
text produced by the enabled runtime policy even when a resource limit makes
the diagnostic incomplete. They do not force formatting callers to interpret a
completion reason that they cannot act on. Program logic that needs completeness
must call the runtime API and inspect its summary explicitly.

Installing a disabled application default is an intentional process-wide
debugging escape hatch and makes subsequent generated `Debug`, `Display`, and
`Serialize` calls restore source values. The framework does not authorize that
choice; callers own its environment controls, timing, and confidentiality
consequences. Explicit runtime redactors, composers, and batches keep the policy
snapshot with which they were created.

For parsed JSON that must remain borrowed and unchanged, use the runtime API
`Redactor::redact_json_value(&serde_json::Value)` or
`Redactor::inspect_json_value(&serde_json::Value)`.

## Learn More

See the [English user guide](doc/user_guide.md), [中文用户手册](doc/user_guide.zh_CN.md),
[API documentation](https://docs.rs/qubit-redact-derive), and the
[runtime crate](https://github.com/qubit-ltd/rs-redact).

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
