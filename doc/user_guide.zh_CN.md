# qubit-redact 用户指南

[English](user_guide.md) · [README](../README.zh_CN.md) · [API 文档](https://docs.rs/qubit-redact)

本指南适用于 `qubit-redact` 0.5，要求 Rust 1.94 或更高版本。它面向需要把多处来源的诊断
数据组合起来、又不希望每处数据各自决定是否泄露秘密信息或占用多少预算的 Rust 应用和库作者。

## 手册目标与读者

当一条诊断事件同时包含可信的程序文本和不可信字段、领域对象、命令行、JSON、HTTP 数据或 URI
时，适合使用本库。先构建 policy；每段事件文本使用一个 composer，每批独立结果使用一个 batch；
只发布已经完成的输出。若只需要处理一个值，可直接调用 `Redactor::redact_*`，它会替你创建并完成
一个 batch。

## 概念模型

正常路径包含五个对象：

1. `RedactionPolicy` 是不可变快照，保存字段规则、掩码方式、格式行为和资源上限。
2. `Redactor` 共享该快照并创建 composer 与 batch。`standard()` 与 `strict()` 是固定 policy；
   `application_default()` 是 `Redact::redacted()` 使用的进程级快照。
3. `RedactedTextComposer` 以消费式链调用构造一段有序文本，并发布 `RedactionTextOutput`。
4. `RedactionBatch` 以可变借用累积独立结果，返回不透明的 `RedactionBatchHandle`，并发布
   `RedactionBatchOutput`。
5. 两个对象都由消费式 `finish()` 发布，且各自拥有独立的预算与摘要。

```text
policy 快照 -> Redactor -> text_composer() -> 有序文本 -> RedactionTextOutput
                     └-> batch()         -> handle 集合 -> RedactionBatchOutput
```

摘要会记录完成状态（`Complete`、`Truncated`、`Exhausted`）、原因和资源用量。程序应以它作为
安全降级的依据，不要解析替换后的文本来推断状态。

## 贯穿场景：安全记录一次请求失败

某 API 客户端既要在可读的失败日志中写入 `request_id`，也要把 URL 与 JSON 错误 body 发送到
遥测系统。`access_token` 和 `password` 不能出现在任何发布结果中；所有片段共享同一组输入、
输出和遍历预算；URL 与 body 要等 batch 完成后才能读取。

## 安装与最小配置

启用本场景实际使用的集成：

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http", "json", "uri"] }
```

`build()` 之后 policy 不可变。各 namespace 闭包先在 draft 中操作；如果配置无效，会返回
`PolicyError`，原 builder 不会被部分更新：

```rust
use qubit_redact::RedactionPolicy;

let policy = RedactionPolicy::builder()
    .fields(|fields| {
        fields
            .secret_sensitive("password")
            .secret_sensitive("access_token");
    })?
    .limits(|limits| {
        limits
            .max_input_bytes(64 * 1024)
            .max_output_bytes(16 * 1024)
            .max_nodes(1024)
            .max_collection_items(256)
            .max_depth(32);
    })?
    .build()?;

# Ok::<(), qubit_redact::PolicyError>(())
```

未知标量字段也必须遮蔽时，可从 `Redactor::strict()` 开始。只有在已明确审核哪些字段允许可见
之后，才应构建自定义 policy。

## 核心工作流

### 分别组装事件文本和单项结果

composer 只生成文本，batch 只生成可解析项；二者不混用，也不会共享预算。

```rust
use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

# let policy = RedactionPolicy::strict();
let redactor = Redactor::new(policy);
let output = redactor
    .text_composer()
    .literal("request failed: ")
    .field("request_id", "req-42")
    .finish();

let mut batch = redactor.batch();
let url = batch.redact_http_url(
    "https://api.example.test/users?access_token=raw-token",
);
let content_type = HeaderValue::from_static("application/json");
let body = batch.redact_http_body(
    BodyCapture::complete(br#"{"password":"raw-password"}"#),
    Some(&content_type),
);
let batch_output = batch.finish();
let safe_url = batch_output.resolve(url)?;
let safe_body = batch_output.resolve(body)?;

assert_eq!(output.text().as_str(), "request failed: <redacted>");
assert_eq!(
    safe_url.text().as_str(),
    "https://api.example.test/<redacted>?access_token=%3Credacted%3E",
);
assert_eq!(safe_body.text().as_str(), r#"{"password":"<redacted>"}"#);
assert_eq!(output.summary().usage().output_bytes(), output.text().as_str().len());
assert_eq!(batch_output.summary().usage().output_bytes(),
           safe_url.text().as_str().len() + safe_body.text().as_str().len());

# Ok::<(), qubit_redact::RedactionBatchHandleError>(())
```

聚合文本和单项结果是刻意分离的输出。使用另一个 batch 的输出解析 handle 时，会得到
`DifferentBatch`。

### 为每次发布创建新对象

composer 和 batch 都是一次性对象；需要下一次发布时，从同一 `Redactor` 新建对象：

```rust
use qubit_redact::Redactor;

let redactor = Redactor::strict();
let first = redactor.text_composer().literal("first").finish();
let second = redactor.text_composer().literal("second").finish();

assert_eq!(first.text().as_str(), "first");
assert_eq!(second.text().as_str(), "second");
```

每个独立的文本或 batch 工作流应持有自己的对象；`Redactor` 及其不可变 policy 快照可以共享。

### 显式描述领域对象

实现 `Redact`，明确说明领域类型如何遍历。writer 不会自行猜测字段是否敏感：

```rust
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;
use qubit_redact::Sensitivity;

struct Account {
    name: String,
    password: String,
}

impl Redact for Account {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Account", |fields| {
            fields.unredacted("name", || self.name.as_str());
            fields.sensitive(Sensitivity::Secret, "password", || {
                self.password.as_str()
            });
        });
    }
}
```

`unredacted` 会绕过字段名 policy，必须经过独立审查。`sensitive` 指定最低敏感度；`nested`
委托给另一个 `Redact` 值；`json` 遵循当前 JSON policy。`skip` 仅用于既不应访问也不应输出的字段。

## 进阶用法

### 格式与一次性操作

所有格式都使用同一套 runtime 实现。composer 提供聚合 namespace，batch 提供单项方法；
`Redactor::redact_*` 提供一次性入口。

| 格式 | 聚合 namespace | 代表性单项方法 |
| --- | --- | --- |
| argv | `composer.argv(...)` | `batch.redact_argv(items)` |
| 环境变量 | `composer.env(...)` | `batch.redact_env(name, value)` |
| 进程 | `composer.process(...)` | `batch.redact_process(...)` |
| JSON | `composer.json(...)` | `batch.redact_json(text)` |
| HTTP | `composer.http(...)` | `batch.redact_http_url/body/headers` |
| URI | `composer.uri(...)` | `batch.redact_uri(text)` |

集合操作会为整个集合创建一个 handle，但每个元素仍会分别消耗集合和结构记账。HTTP 将 URL、
headers 和 body 刻意拆成不同的单项操作。

### 应用默认快照

`Default for Redactor` 始终等价于 `standard()`。如需替换 `Redact::redacted()` 使用的快照，
可原子替换完整 redactor：

```rust
use qubit_redact::Redactor;

let previous = Redactor::replace_application_default(Redactor::strict());
let current = Redactor::application_default();
let _ = Redactor::replace_application_default(previous);
assert_eq!(current, Redactor::strict());
```

已经创建的 redactor、composer 和 batch 继续使用旧快照。读取方只会观察到完整的旧 policy 或完整的新
policy，不会看到两者混合的状态。

### 如实报告上游截断

HTTP body 在进入本库前已被截断时：如果知道原始长度，使用
`BodyCapture::truncated(bytes, total_len)`；不知道时使用
`BodyCapture::truncated_unknown(bytes)`。摘要会包含 `SourceTruncated`；遗漏字节数未知时，
`omitted_input_bytes()` 返回 `None`。

## 错误与诊断

构建 policy 可能返回 `PolicyError`。解析 batch handle 只会返回 `DifferentBatch` 或
`MissingItem`。

输入、输出和结构上限，非法 JSON/URI、不支持的内容、非法 content type 及上游截断，都是安全的
脱敏结果，而非 `finish()` 错误。请检查 `output.summary()` 的完成状态和原因。`Exhausted`
表示完整的安全替代内容已无法放入共享输出预算；之后的单项调用不会再检查输入，而是返回当前
batch 中唯一的空 exhausted item。

用户提供的 writer 或 adapter 发生 panic 时，当前未发布对象会被丢弃，随后继续展开 panic。
composer 会随展开被消费；batch 会安装新的空 identity，因此调用方使用 `catch_unwind` 后可以
继续复用该 batch，但 panic 前产生的 handle 无法解析。

## 排障

- **单项文本为空且为 exhausted。** 检查 `OutputLimitReached`；提高 `max_output_bytes`，或减少
  同一事件中更早的输出。
- **收到 `DifferentBatch`。** 使用创建 handle 后那次 `batch.finish()` 返回的准确
  `RedactionBatchOutput` 进行解析。
- **出现意外明文。** 检查显式 `unredacted` 调用与未标注的 derive 字段；运行期字段规则不会修正
  这两条路径。
- **过早截断。** 对比 `RedactionUsage` 中提交与检查的输入、访问的节点/集合项、最大深度和上限。
- **找不到 JSON、HTTP 或 URI API。** 在 Cargo 中启用对应 feature。

## 限制与最佳实践

- `literal` 只能接收程序内的 `&'static str` 文本；运行时文本必须进入脱敏操作。
- 审查每个新增领域字段及每次 `unredacted` 的使用。
- 资源上限分别覆盖一段 composer 文本或一批 batch 结果。
- 只有 `finish()` 发布的 `RedactionTextOutput` 或 `RedactionBatchOutput` 中的结果才是最终的强类型脱敏边界。

## 延伸阅读

- [中文 README](../README.zh_CN.md)
- [English user guide](user_guide.md)
- [API 文档](https://docs.rs/qubit-redact)
- [核心设计](design.zh_CN.md)
