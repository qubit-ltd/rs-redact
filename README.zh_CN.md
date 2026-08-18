# qubit-redact

面向字段、命令参数、环境变量、JSON、HTTP、URI 和 Rust 领域对象的规则驱动脱敏库。

## Direct 操作

Direct adapter 是彼此独立的操作，返回拥有所有权的结果，不共享输入或输出字节计数：

```rust
use qubit_redact::Redactor;

let redactor = Redactor::standard();
let output = redactor.redact_field("password", "secret");
assert_eq!(output.as_str(), "<redacted>");

let url = redactor.http().redact_url_str("https://example.test/?token=secret");
assert!(!url.as_str().contains("secret"));
```

## 原子 Session

只有在需要一次性发布多个具名 adapter 结果时才使用 Session。每个结果独立准备，
`finish` 要么发布整个批次，要么拒绝批次。

`RedactionOutput` 提供 `text()`、`summary()`、`into_text()` 和 `into_parts()`；完成状态
只有 `Complete` 与 `Truncated`，summary 保留结构、解析和输入 capture 原因。

## Domain 与 derive

实现 `Redact` 或使用 `qubit-redact-derive` 派生。嵌套值通过 writer-owned traversal
上下文渲染，每个顶层 view 拥有独立结构预算，避免泄漏原始敏感值。

## 安全模型

结构限制来自 `qubit-budget`；JSON 使用 JSON value limits；HTTP `BodyCapture` 报告
输入长度和入口截断状态，不再使用策略级共享字节计数。任何展示上限都由目标 writer
显式拥有。

## 许可证

Apache-2.0。
