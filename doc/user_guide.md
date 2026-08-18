# User guide

Start with `Redactor::standard()` and use direct adapters for one operation:

```rust
use qubit_redact::Redactor;
let output = Redactor::standard().redact_field("token", "raw-token");
assert_eq!(output.as_str(), "****");
```

For a multi-value diagnostic, stage keyed results in a `RedactionSession` and
call `finish`. Publication is atomic and each adapter consumes a finite input
iterator exactly once.

JSON uses the policy's `JsonValueLimits`; HTTP uses `BodyCapture` metadata and
fail-closed parsing; URI results expose component and reason metadata. None of
these paths uses a policy-wide input/output byte budget.

Domain implementations should write through `RedactionWriter`. Derived structs,
maps, and nested JSON values use the writer's independent structural context.
