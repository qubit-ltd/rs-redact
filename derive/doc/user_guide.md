# qubit-redact-derive User Guide

[README](../README.md) · [中文用户手册](user_guide.zh_CN.md) · [Runtime User Guide](../../doc/user_guide.md) · [Derive API](https://docs.rs/qubit-redact-derive)

Qubit Redact Derive turns field-level redaction decisions into generated
implementations for Rust domain types. It complements the
[`qubit-redact`](https://docs.rs/qubit-redact) runtime: the runtime owns
policies and masks; this crate applies those decisions to structs and enums.

## Contents

- [Installation and example requirements](#installation-and-example-requirements)
- [Core concepts](#core-concepts)
- [1. Create a borrowed view with `Redact`](#1-create-a-borrowed-view-with-redact)
- [2. Choose field handling](#2-choose-field-handling)
- [3. Supported structs and enums](#3-supported-structs-and-enums)
- [4. Replace logical values with `RedactMut`](#4-replace-logical-values-with-redactmut)
- [5. Generate `Debug` and `Display`](#5-generate-debug-and-display)
- [6. Serialize a redacted view with Serde](#6-serialize-a-redacted-view-with-serde)
- [7. Resolve dependencies and diagnose errors](#7-resolve-dependencies-and-diagnose-errors)
- [Security boundaries and verification](#security-boundaries-and-verification)

## Installation and example requirements

The package is `qubit-redact-derive`; import its macros as
`qubit_redact_derive`. The generated implementations depend on the runtime
crate, so `qubit-redact` must be a direct dependency. Every runnable Rust
example in this guide is a complete `main.rs`: use the dependency block for
its section and run `cargo run`.

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["serde"] }
qubit-redact-derive = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

The `serde` feature is needed only for `#[redact(serde)]`. Without it, the
basic `Redact` and `RedactMut` derives have no Serde requirement.

## Core concepts

`Redact` and `RedactMut` are both macro names and runtime trait names.
Import them separately to make the boundary explicit:

```rust
use qubit_redact::{Redact as _, RedactMut as _};
use qubit_redact_derive::{Redact, RedactMut};
```

`#[derive(Redact)]` implements the runtime `Redact` trait. Calling
`redacted()` returns `Redacted<T>`, a lazy borrowed view that owns a snapshot
of the policy and leaves `T` unchanged. `redacted_with(&policy)` chooses an
explicit policy snapshot.

`#[derive(RedactMut)]` implements `RedactMut`. Calling
`redact_in_place()` uses the current default policy; calling
`redact_in_place_with(&policy)` chooses an explicit snapshot and replaces
logical values in the object.

| Boundary | Prefer | Why |
| --- | --- | --- |
| Debug output, error context, structured diagnostics | `Redact` | The source object remains available and the redacted view is explicit. |
| A later API must receive a logically redacted object | `RedactMut` | Mutation is deliberate and visible at the call site. |
| Policy isolation in a test or subsystem | `redacted_with` or `redact_in_place_with` | The call site owns the policy rather than using the process default. |

## 1. Create a borrowed view with `Redact`

Start with a field that should always be masked at a known sensitivity:

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Login {
    account: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let login = Login {
        account: "ada".to_owned(),
        password: "raw-password".to_owned(),
    };

    let diagnostic = format!("{:?}", login.redacted());
    assert!(diagnostic.contains("ada"));
    assert!(!diagnostic.contains("raw-password"));
    assert_eq!(login.password, "raw-password");
}
```

`Redacted<T>` formats the generated redacted representation. It is not a
second domain object and does not expose an owned replacement of `T`.

## 2. Choose field handling

Each field may have no `redact` attribute or exactly one of the following
modes. Combining modes, repeating one, adding arguments to a bare mode, or
using an empty `#[redact()]` attribute is a compile error.

| Attribute | Immutable `Redact` behavior | Mutable `RedactMut` behavior | Required runtime capability |
| --- | --- | --- | --- |
| none | Formats the field with ordinary `Debug`. | Leaves the field unchanged. | `Debug` for formatting. |
| `level = "low"`, `"medium"`, `"high"`, or `"secret"` | Uses the selected mask. | Replaces the logical value with the selected mask. | `RedactValue` / `RedactValueMut`. |
| `skip` | Omits the field. | Leaves the field unchanged. | None. |
| `nested` | Formats the nested value through its `Redact` implementation. | Calls nested `RedactMut`. | `Redact` / `RedactMut`. |
| `map` | Redacts text-keyed map values with keys and the full policy. | Redacts those map values in place. | `RedactMapValue` / `RedactMapValueMut`. |

Sensitivity spelling is lowercase and exact. These are the only accepted
literals: `low`, `medium`, `high`, and `secret`.

The following type demonstrates every immutable mode:

```rust
use std::collections::BTreeMap;

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Request {
    request_id: String,
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
    #[redact(map)]
    metadata: BTreeMap<String, String>,
}

fn main() {
    let request = Request {
        request_id: "req-7".to_owned(),
        token: "raw-token".to_owned(),
        internal_note: "operator-only".to_owned(),
        metadata: BTreeMap::from([("api_key".to_owned(), "raw-key".to_owned())]),
    };
    let output = format!("{:?}", request.redacted());
    assert!(output.contains("req-7"));
    assert!(!output.contains("raw-token"));
    assert!(!output.contains("operator-only"));
}
```

Do not expect unmarked fields to be discovered or recursively inspected. If a
field contains a domain object, use `nested`; if it is a supported text-keyed
map, use `map`.

## 3. Supported structs and enums

`Redact` accepts named, tuple, and unit structs. It also accepts enums with
named, tuple, and unit variants. Field annotations work in every supported
shape.

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
enum Event {
    Login {
        user: String,
        #[redact(level = "secret")]
        token: String,
    },
    ApiKey(#[redact(level = "secret")] String),
    Ready,
}

fn main() {
    let event = Event::Login {
        user: "ada".to_owned(),
        token: "raw-token".to_owned(),
    };
    assert!(!format!("{:?}", event.redacted()).contains("raw-token"));
    assert_eq!(format!("{:?}", Event::Ready.redacted()), "Ready");
}
```

Unions are rejected. The generated implementation preserves generic parameters
and where clauses, while Rust verifies the field capabilities selected by each
attribute.

## 4. Replace logical values with `RedactMut`

`RedactMut` uses the same field grammar. It changes only fields marked
`level`, `nested`, or `map`; plain and `skip` fields remain unchanged.

```rust
use qubit_redact::RedactMut as _;
use qubit_redact_derive::RedactMut;

#[derive(RedactMut)]
struct Credentials {
    account: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    audit_note: String,
}

fn main() {
    let mut value = Credentials {
        account: "ada".to_owned(),
        password: "raw-password".to_owned(),
        audit_note: "keep".to_owned(),
    };

    value.redact_in_place();
    assert_eq!(value.password, "<redacted>");
    assert_eq!(value.audit_note, "keep");
}
```

Use `into_redacted()` to consume and redact a value, or `to_redacted()` to
clone and redact it. Neither operation is memory zeroization.

## 5. Generate `Debug` and `Display`

On a `Redact` derive, `#[redact(debug)]` and `#[redact(display)]` generate
formatting implementations for the original type. Both format through a
snapshot of the current process-wide default policy.

```rust
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(debug, display)]
struct Secret {
    #[redact(level = "secret")]
    value: String,
}

fn main() {
    let value = Secret {
        value: "raw-secret".to_owned(),
    };
    assert!(!format!("{value:?}").contains("raw-secret"));
    assert!(!format!("{value}").contains("raw-secret"));
}
```

Do not request generated `Debug` or `Display` when the type already has an
implementation of that trait. For a boundary that needs a non-default policy,
avoid generated formatting and format `value.redacted_with(&policy)` instead.

## 6. Serialize a redacted view with Serde

Serialization is opt-in. Add `#[redact(serde)]` to a `Redact` derive,
enable `qubit-redact`'s `serde` feature, and declare `serde` directly.
`Redacted<T>` serializes but does not deserialize.

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
#[serde(rename_all = "camelCase")]
struct LoginEvent {
    account_name: String,
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event = LoginEvent {
        account_name: "ada".to_owned(),
        token: "raw-token".to_owned(),
        internal_note: "operator-only".to_owned(),
    };

    let json = serde_json::to_string(&event.redacted())?;
    assert!(json.contains("accountName"));
    assert!(!json.contains("raw-token"));
    assert!(!json.contains("internal_note"));
    Ok(())
}
```

The macro preserves the currently supported Serde wire controls needed by the
redacted representation:

| Serde control | Redacted behavior |
| --- | --- |
| `rename`, `rename_all`, `rename_all_fields` | Applies the configured field and variant names. |
| `skip`, `skip_serializing`, `skip_serializing_if` | Omits a field according to its serialization rule; `skip` and `skip_serializing` also omit an enum variant. |
| External tagging | Preserves the default enum wire shape. |
| `tag` | Preserves internally tagged enum output. |
| `tag` with `content` | Preserves adjacently tagged enum output. |
| `untagged` | Preserves untagged enum output. |

The macro reports a targeted error when `#[redact(serde)]` is used without
the runtime `serde` feature or when an unsupported Serde control is present.

## 7. Resolve dependencies and diagnose errors

Generated code resolves the runtime through Cargo metadata. A renamed runtime
dependency is valid:

```toml
[dependencies]
redaction = { package = "qubit-redact", version = "0.5" }
qubit-redact-derive = "0.5"
```

The derive macro still emits the correct path. Do not rely on a transitive
runtime dependency: add it directly to the package that uses the derive.

| Situation | What to do |
| --- | --- |
| The runtime crate cannot be resolved | Add `qubit-redact` as a direct dependency, or correct its Cargo rename. |
| `#[redact(serde)]` reports a missing feature | Enable `qubit-redact = { features = ["serde"] }`. |
| Serde imports fail in the derived package | Add a direct `serde` dependency with the required derive feature. |
| An attribute is rejected | Use exactly one field mode: `level = "..."`, `skip`, `nested`, or `map`; use bare container controls. |
| A trait-bound error points at a field | Choose a mode supported by that field type, or implement the required runtime trait. |
| A union is rejected | Derive only on supported struct and enum forms. |

## Security boundaries and verification

- The macro does not act as a secret detector. Every sensitive field must be
  marked or contained by an explicitly nested or mapped boundary.
- `Redact` protects only the representation obtained from `redacted()` or
  `redacted_with()`; logging the original value remains unsafe.
- `skip` removes a field from a derived view or serialized redacted output,
  but leaves the source object intact.
- `RedactMut` performs logical replacement only. Use a dedicated
  zeroization design when memory erasure is required.
- Treat `#[redact(debug)]`, `#[redact(display)]`, and every default-policy
  call as process-wide policy decisions.

Before publishing changes to derives or examples, run:

```bash
cargo test --all-features
./ci-check.sh
```
