# qubit-redact 用户指南

[English](user_guide.md) · [README](../README.zh_CN.md) ·
[API 文档](https://docs.rs/qubit-redact)

本指南适用于 `qubit-redact` 0.5，要求 Rust 1.94 或更高版本。面向需要把多种数据组合为
诊断信息、同时又必须保持统一脱敏策略与资源边界的应用和库作者。

## 概念模型

正常工作流由四个对象组成：

1. `RedactionPolicy` 是不可变快照，包含字段规则、掩码方式、格式策略与 transaction
   资源上限。
2. `Redactor` 持有 `Arc` 快照。`standard()` 与 `strict()` 的结果是确定的；
   `application_default()` 则是 `Redact::redacted()` 使用的进程级快照。
3. `RedactionSession` 可以复用，但当前 transaction 始终私有。聚合 API 追加组合文本，
   单项 API 只返回不透明的 `RedactionHandle`。
4. `finish()` 原子发布 `RedactionSessionOutput`，随即用同一 policy 开始新 transaction。
   输出包含聚合文本、整轮 summary，以及供 `resolve()` 使用的单项结果。

```text
policy 快照 -> 可复用 session -> 私有 transaction -> finish()
                                  |               -> 聚合文本
                                  +-> 不透明 handle -> 单项结果
```

完成状态分为 `Complete`、`Truncated`、`Exhausted`。reason 区分输入、输出、遍历、
深度、上游截断与格式错误；usage 分别记录提交/检查的输入、保留的输出、访问的结构、
最大深度，以及已知或未知的遗漏字节数。

## 贯穿场景：安全记录一次请求失败

某 API 客户端需要输出一条含 request ID 与领域对象的日志，同时把 URL 和响应 body
分别交给结构化遥测。目标是：

- access token 和 password 不出现在任何已发布文本中；
- 所有片段共用同一输出与遍历上限；
- transaction 完成前无法读取 URL/body handle 的文本；
- 同一个 session 可以继续处理下一次请求。

## 安装与最小配置

只启用应用实际使用的格式：

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http", "json", "uri"] }
```

先构建不可变 policy。namespace 闭包修改临时 draft，验证成功后才整体应用：

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

希望默认安全关闭时可从 `Redactor::strict()` 开始；只有在应用已经审查哪些字段允许可见
之后，才适合使用自定义 policy。

## 核心工作流

### 组合聚合文本并单独解析结果

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
    BodyCapture::complete(br#"{"password":"raw-password"}"#),
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

聚合调用不创建 handle，单项调用也不会写入聚合文本；两者仍共同消耗 transaction 预算，
并进入整轮 summary。handle 如果拿到另一轮输出上解析，会返回 `DifferentTransaction`。

### 复用 session

`finish(&mut self)` 会立即安装下一轮 transaction：

```rust
use qubit_redact::Redactor;

let mut session = Redactor::strict().session();
let first = session.literal("first").finish();
let second = session.literal("second").finish();

assert_eq!(first.text().as_str(), "first");
assert_eq!(second.text().as_str(), "second");
```

### 领域对象

每个 `Redact` 实现都必须显式定义 `write_redacted`：

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

`unredacted` 会刻意绕过字段名 policy，只能用于已经独立确认可公开的内容。`sensitive`
把显式 level 作为最低敏感度；`nested` 委托另一个 `Redact` 值；`json` 使用当前 JSON
policy。本库不会根据字段名或值内容自行猜测敏感性。

动态 key 表示值名称的 map，应把实现 `ExactSizeIterator` 的迭代器传给 `map`。writer 会在
渲染每个值前分别按其 key 分类：

```rust
use std::collections::BTreeMap;

# use qubit_redact::Redact;
# use qubit_redact::RedactionWriter;
struct Attributes(BTreeMap<String, String>);

impl Redact for Attributes {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Attributes", |fields| {
            fields.map("values", self.0.iter());
        });
    }
}
```

精确剩余长度让 writer 能在共享遍历预算耗尽前停止，不会再推进下一个 entry。

## 进阶用法

### 六类格式

每类格式都提供聚合 namespace、单项 handle 方法，以及 `Redactor::redact_*` 一次性便利
入口：

| 格式 | 聚合 namespace | 代表性单项方法 |
| --- | --- | --- |
| argv | `session.argv(...)` | `session.redact_argv(items)` |
| env | `session.env(...)` | `session.redact_env(name, value)` |
| process | `session.process(...)` | `session.redact_process(...)` |
| JSON | `session.json(...)` | `session.redact_json(text)` |
| HTTP | `session.http(...)` | `redact_http_url/body/headers` |
| URI | `session.uri(...)` | `session.redact_uri(text)` |

集合操作为整个集合创建一个 handle，但每个元素仍分别消耗 collection 和结构计数。
HTTP 的 URL、headers、body 使用不同单项方法；项目不提供含义不清的多操作
`redact_http` handle。

### 应用默认快照

`Default for Redactor` 始终等价于 `standard()`，不会读取可变全局状态。只需要替换
`Redact::redacted()` 使用的快照时：

```rust
use qubit_redact::Redactor;

let previous = Redactor::replace_application_default(Redactor::strict());
let current = Redactor::application_default();
let _ = Redactor::replace_application_default(previous);
assert_eq!(current, Redactor::strict());
```

已有 redactor 与 session 继续持有旧快照。替换操作覆盖完整 policy，读取方不会看到两份
policy 混合后的状态。

### 上游已截断的 HTTP body

源总长度已知时使用 `BodyCapture::truncated(bytes, total_len)`；未知时使用
`BodyCapture::truncated_unknown(bytes)`。summary 会包含 `SourceTruncated`；源长度未知时
`omitted_input_bytes()` 为 `None`。上游已经丢失字节时，不能伪装成 complete capture。

## 错误与诊断

policy 构建错误使用 `PolicyError`；handle 解析错误只有 `DifferentTransaction` 与
`MissingItem`。

输入/输出/结构上限、非法 JSON/URI/content type、不支持的内容和上游截断，都属于安全
脱敏结果，不会让 `finish()` 返回错误。应用应读取 `output.summary()`，不要解析文本 marker。
`Exhausted` 表示当前操作连完整的安全替代文本也无法放进共享输出预算。之后的单项调用不会
检查输入，而是解析到当前 transaction 中唯一的空 exhausted item。

用户 writer 或 adapter 代码 panic 时，当前 transaction 会整体丢弃，session 安装新
transaction 后继续展开 panic。调用方若用 `catch_unwind` 捕获，session 仍可复用；失败
transaction 创建的 handle 永远无法解析。

## 排障

- 单项文本为空且状态为 `Exhausted`：检查 `OutputLimitReached`；提高
  `max_output_bytes`，或减少同一 transaction 中更早的输出。
- 返回 `DifferentTransaction`：必须在创建 handle 的那次 `finish()` 返回值上解析。
- 出现意外明文：检查未标注的 derive 字段与显式 `unredacted` 调用；两条路径都不查询
  运行期字段 policy。
- 过早截断：对比 `RedactionUsage` 中提交/检查的输入字节、节点、集合项和最大深度。
- 找不到 JSON/HTTP/URI 方法：启用对应 Cargo feature。

## 限制与最佳实践

- `literal` 只用于编译期程序文本，不能作为运行期输入的绕行入口。
- 每次新增领域字段都要审查；只有字段既不应访问也不应输出时才使用 `skip`。
- 每个独立可变工作流使用自己的 session；不可变的 `Redactor` policy 快照可以复用。
- 资源上限应按整条诊断事件设置，而不是分别为各格式设置互不相关的额度。
- 只有 `finish()` 发布的文本或 `RedactionOutput` 才是最终强类型脱敏边界。

## 延伸阅读

- [中文 README](../README.zh_CN.md)
- [English user guide](user_guide.md)
- [API 文档](https://docs.rs/qubit-redact)
- [事务式架构设计](2026-08-19-rs-redact-transactional-redesign-design.md)
