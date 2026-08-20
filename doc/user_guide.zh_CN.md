# qubit-redact 用户指南

[English](user_guide.md) · [README](../README.zh_CN.md) · [API 文档](https://docs.rs/qubit-redact)

本指南适用于 `qubit-redact` 0.5，要求 Rust 1.94 或更高版本。它面向需要把多处来源的诊断
数据组合起来、又不希望每处数据各自决定是否泄露秘密信息或占用多少预算的 Rust 应用和库作者。

## 手册目标与读者

当一条诊断事件同时包含可信的程序文本和不可信字段、领域对象、命令行、JSON、HTTP 数据或 URI
时，适合使用本库。先构建 policy；每个独立的可变事件使用一个 session；只发布已经完成的输出。
若只需要处理一个值，可直接调用 `Redactor::redact_*`，它会替你创建并完成这一轮 transaction。

## 概念模型

正常路径包含四个对象：

1. `RedactionPolicy` 是不可变快照，保存字段规则、掩码方式、格式行为和资源上限。
2. `Redactor` 共享该快照并创建 session。`standard()` 与 `strict()` 是固定 policy；
   `application_default()` 是 `Redact::redacted()` 使用的进程级快照。
3. `RedactionSession` 持有一轮私有、可变的 transaction。聚合调用向事件文本追加内容；单项调用
   返回不透明的 `RedactionHandle`。
4. `finish()` 发布 `RedactionSessionOutput`，其中包含聚合文本、`RedactionSummary` 和解析
   handle 所需的单项结果；它也会立即用原 policy 为 session 开始下一轮 transaction。

```text
policy 快照 -> 可复用 session -> 私有 transaction -> finish()
                                  |                    -> 聚合文本
                                  +-> 不透明 handle     -> 单项结果
```

摘要会记录完成状态（`Complete`、`Truncated`、`Exhausted`）、原因和资源用量。程序应以它作为
安全降级的依据，不要解析替换后的文本来推断状态。

## 贯穿场景：安全记录一次请求失败

某 API 客户端既要在可读的失败日志中写入 `request_id`，也要把 URL 与 JSON 错误 body 发送到
遥测系统。`access_token` 和 `password` 不能出现在任何发布结果中；所有片段共享同一组输入、
输出和遍历预算；URL 与 body 要等 transaction 完成后才能读取。

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

### 组装事件并解析单项结果

聚合操作返回 `&mut RedactionSession`，单项操作返回 handle；二者都会在 `finish()` 前保持未发布。

```rust
use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

# let policy = RedactionPolicy::strict();
let mut session = Redactor::new(policy).session();
let url = session.redact_http_url(
    "https://api.example.test/users?access_token=raw-token",
);
let content_type = HeaderValue::from_static("application/json");
let body = session.redact_http_body(
    BodyCapture::complete(br#"{\"password\":\"raw-password\"}"#),
    Some(&content_type),
);
session
    .literal("request failed: ")
    .field("request_id", "req-42");

let output = session.finish();
let safe_url = output.resolve(url)?;
let safe_body = output.resolve(body)?;

assert!(!safe_url.text().as_str().contains("raw-token"));
assert!(!safe_body.text().as_str().contains("raw-password"));
assert_eq!(output.summary().usage().output_bytes(),
           output.text().as_str().len()
               + safe_url.text().as_str().len()
               + safe_body.text().as_str().len());

# Ok::<(), qubit_redact::RedactionHandleError>(())
```

聚合文本和单项结果共用同一轮资源记账，但它们是刻意分离的输出。使用另一轮输出解析 handle 时，
会得到 `DifferentTransaction`。

### 复用 session

完成一轮事件后，session 立即安装下一轮 transaction：

```rust
use qubit_redact::Redactor;

let mut session = Redactor::strict().session();
let first = session.literal("first").finish();
let second = session.literal("second").finish();

assert_eq!(first.text().as_str(), "first");
assert_eq!(second.text().as_str(), "second");
```

每个独立的可变工作流应持有自己的 session；`Redactor` 及其不可变 policy 快照可以共享。

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

所有格式都使用同一套 transaction runtime。session 提供聚合 namespace 与单项方法；
`Redactor::redact_*` 提供一次性入口。

| 格式 | 聚合 namespace | 代表性单项方法 |
| --- | --- | --- |
| argv | `session.argv(...)` | `session.redact_argv(items)` |
| 环境变量 | `session.env(...)` | `session.redact_env(name, value)` |
| 进程 | `session.process(...)` | `session.redact_process(...)` |
| JSON | `session.json(...)` | `session.redact_json(text)` |
| HTTP | `session.http(...)` | `redact_http_url/body/headers` |
| URI | `session.uri(...)` | `session.redact_uri(text)` |

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

已经创建的 redactor 和 session 继续使用旧快照。读取方只会观察到完整的旧 policy 或完整的新
policy，不会看到两者混合的状态。

### 如实报告上游截断

HTTP body 在进入本库前已被截断时：如果知道原始长度，使用
`BodyCapture::truncated(bytes, total_len)`；不知道时使用
`BodyCapture::truncated_unknown(bytes)`。摘要会包含 `SourceTruncated`；遗漏字节数未知时，
`omitted_input_bytes()` 返回 `None`。

## 错误与诊断

构建 policy 可能返回 `PolicyError`。解析 handle 只会返回 `DifferentTransaction` 或
`MissingItem`。

输入、输出和结构上限，非法 JSON/URI、不支持的内容、非法 content type 及上游截断，都是安全的
脱敏结果，而非 `finish()` 错误。请检查 `output.summary()` 的完成状态和原因。`Exhausted`
表示完整的安全替代内容已无法放入共享输出预算；之后的单项调用不会再检查输入，而是返回当前
transaction 中唯一的空 exhausted item。

用户提供的 writer 或 adapter 发生 panic 时，当前 transaction 会被丢弃，session 安装新一轮
transaction，随后继续展开 panic。调用方使用 `catch_unwind` 后仍可复用 session，但失败事件中
产生的 handle 无法解析。

## 排障

- **单项文本为空且为 exhausted。** 检查 `OutputLimitReached`；提高 `max_output_bytes`，或减少
  同一事件中更早的输出。
- **收到 `DifferentTransaction`。** 使用创建 handle 后那次 `finish()` 返回的准确
  `RedactionSessionOutput` 进行解析。
- **出现意外明文。** 检查显式 `unredacted` 调用与未标注的 derive 字段；运行期字段规则不会修正
  这两条路径。
- **过早截断。** 对比 `RedactionUsage` 中提交与检查的输入、访问的节点/集合项、最大深度和上限。
- **找不到 JSON、HTTP 或 URI API。** 在 Cargo 中启用对应 feature。

## 限制与最佳实践

- `literal` 只能接收程序内的 `&'static str` 文本；运行时文本必须进入脱敏操作。
- 审查每个新增领域字段及每次 `unredacted` 的使用。
- 资源上限应覆盖整条诊断事件，包括单独解析的结果。
- 只有 `finish()` 发布的文本或返回的 `RedactionOutput` 才是最终的强类型脱敏边界。

## 延伸阅读

- [中文 README](../README.zh_CN.md)
- [English user guide](user_guide.md)
- [API 文档](https://docs.rs/qubit-redact)
- [事务式架构设计](2026-08-19-rs-redact-transactional-redesign-design.md)
