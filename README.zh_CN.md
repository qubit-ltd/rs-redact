# qubit-redact

`qubit-redact` 在一份不可变 policy 下，对标量字段、Rust domain value、argv、环境变量、
进程命令、JSON、HTTP 和 URI 诊断信息脱敏。

## 单项操作

`Redactor` 的便利方法各自创建一个 transaction，并返回 `RedactionOutput`。

```rust
use qubit_redact::Redactor;

let output = Redactor::strict().redact_field("password", "raw-secret");
assert!(!output.text().as_str().contains("raw-secret"));
```

## 一轮诊断 transaction

多段诊断信息应使用 `RedactionSession`，让所有输入、输出和结构预算共享。聚合 API
返回 session 以支持链式调用；只有 `finish()` 发布结果，并把 session 重置为下一轮
transaction 可复用状态。

```rust
use qubit_redact::Redactor;

let mut session = Redactor::strict().session();
session
    .literal("login failed for ")
    .field("user", "Ada")
    .literal(", password: ")
    .field("password", "raw-secret");
let output = session.finish();
assert!(!output.text().as_str().contains("raw-secret"));
```

若需取得某一单项结果，调用 `redact_*` 获得 `RedactionHandle`，并且只能在同一轮
`finish()` 返回的输出上解析：

```rust
use qubit_redact::Redactor;

let mut session = Redactor::strict().session();
let password = session.redact_field("password", "raw-secret");
let output = session.finish();
assert!(!output.resolve(password)?.text().as_str().contains("raw-secret"));
# Ok::<(), qubit_redact::RedactionHandleError>(())
```

`literal` 只接受程序作者写出的 `&'static str`，但仍消耗共享输出预算。动态文本必须
通过相应的脱敏操作处理。

## 应用默认值

`Redactor::default()` 始终是确定性的标准 policy。应用可通过
`Redactor::replace_application_default` 安装供 `Redact::redacted()` 使用的完整快照；
已经创建的 redactor 和 session 保持自己的快照。

## Domain value

可实现 `Redact`，或使用 `qubit-redact-derive`。未标记 `#[redact(...)]` 的字段与显式
`skip` 字段，刻意保持不脱敏；因此必须明确标注所有敏感字段。
`RedactionWriter::literal` 只接收程序字面量，`RedactionWriter::unredacted` 则明确表示
可信的动态内容。

## License

Apache-2.0.
