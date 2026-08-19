# rs-redact 可复用事务式脱敏架构设计

日期：2026-08-19

## 1. 状态与适用范围

本文档取代 `doc/2026-08-17-rs-redact-redesign-design.md` 中关于消费式
`RedactionSession`、隐式字段分类和 keyed session item 的设计。字段匹配、掩码、
UTF-8 安全截断、字符处理与格式解析等成熟算法继续保留，但必须接入本文定义的
唯一 transaction runtime。

适用仓库包括 `rs-redact`、`rs-redact-derive` 以及直接下游 `rs-value`、
`rs-metadata`、`rs-config`、`rs-fs`、`rs-http`、`rs-command` 和
`rs-fs-registry`。

允许破坏性 API 变更，不保留 deprecated alias、兼容 facade 或重复公开路径。

## 2. 核心目标

1. `RedactionSession` 可复用，每次 `finish()` 划定一个原子 transaction。
2. 一轮 transaction 只拥有一份 policy 快照、一组预算、一份聚合文本、一组单项
   结果和一份聚合 summary。
3. `finish()` 前任何中间脱敏文本均不可见。
4. 聚合写入 API 返回 `&mut Self`；单项提取 API 返回 opaque handle。
5. JSON、HTTP、URI、argv、env、process 和 domain writer 全部共享同一 runtime。
6. 预算耗尽与格式降级失败关闭，通过 summary 表达，不作为 transaction 错误。
7. 未标注的 derive 字段明确视为不需要脱敏；框架不猜测字段敏感性。
8. 旧 API 在迁移开始时取消公开，使遗漏迁移立即表现为编译失败。

## 3. 总体数据流

```text
RedactionPolicy
      ↓ Arc snapshot
Redactor
      ↓ session()
RedactionSession ──────────────────────────────────────┐
      │                                                 │
      ├── aggregate APIs → OutputBuffer                 │
      ├── handle APIs    → item ranges                  │
      ├── domain writer  → same TransactionState       │
      └── all formats    → same TransactionState       │
                                                        │
finish() ── atomic publish + reset ── RedactionSessionOutput
                                      ├── text
                                      ├── summary
                                      └── resolve(handle)
```

## 4. Policy 与默认实例

`Redactor` 和 `RedactionSession` 都持有 `Arc<RedactionPolicy>`。session 不借用
redactor，因此可独立长期复用，且应用默认值替换不影响已有实例。

```rust
pub struct Redactor {
    policy: Arc<RedactionPolicy>,
}

impl Redactor {
    pub fn new(policy: RedactionPolicy) -> Self;
    pub fn standard() -> Self;
    pub fn strict() -> Self;
    pub fn policy(&self) -> &RedactionPolicy;
    pub fn session(&self) -> RedactionSession;

    pub fn application_default() -> Self;

    #[must_use]
    pub fn replace_application_default(redactor: Self) -> Self;
}
```

语义固定为：

- `Default for Redactor` 等价于 `standard()`，不读取可变全局状态；
- `RedactionPolicy::default()` 是确定性的标准 policy；
- `application_default()` 返回进程级应用默认值的完整快照；
- `replace_application_default()` 线性化替换完整快照并返回旧值；
- 已有 redactor 和 session 不受替换影响；
- `Redact::redacted()` 使用 `application_default()`；
- `Redact::redacted_with()` 只使用显式 `&Redactor`。

`Redactor::new` 只接受 `RedactionPolicy`。删除 `RedactionConfig` 和
`RedactionConfigBuilder`。

所有 policy namespace 使用消费式事务 builder：

```rust
let policy = RedactionPolicy::builder()
    .fields(|fields| {
        fields
            .secret_sensitive("password")
            .high_sensitive("access_token");
    })?
    .limits(|limits| {
        limits
            .max_input_bytes(64 * 1024)
            .max_output_bytes(16 * 1024)
            .max_nodes(1024)
            .max_collection_items(256)
            .max_depth(32);
    })?
    .http(|http| {
        http.text_body_policy(TextBodyPolicy::Redact);
    })?
    .uri(|uri| {
        uri.path_policy(UriPathPolicy::Redact);
    })?
    .build()?;
```

每个 namespace 写入临时 draft，闭包结束后统一验证，成功后整体应用，失败时
原 builder 不发生部分修改。删除 `edit_fields()` 及所有 `&mut self` 过渡 view。

## 5. 可复用 transaction session

```rust
pub struct RedactionSession {
    policy: Arc<RedactionPolicy>,
    transaction: TransactionState,
}

struct TransactionState {
    id: TransactionId,
    budget: RedactionBudget,
    output: OutputBuffer,
    items: Vec<ItemRange>,
    summary: SummaryBuilder,
    phase: TransactionPhase,
}

enum TransactionPhase {
    Active,
    OutputExhausted,
}
```

一轮 transaction 从 session 创建或上一次 `finish()` 完成后开始。所有追加操作
写入私有暂存状态。`finish()` 通过整体移动发布结果，并立即安装使用同一 policy 的
全新 transaction：

```rust
pub fn finish(&mut self) -> RedactionSessionOutput;
```

`finish()` 无错误返回。非法格式、输入截断和预算不足是安全脱敏结果，通过 summary
表达。移除 `RedactionSessionError`。

## 6. 聚合 API 与单项 handle API

### 6.1 聚合写入

聚合 API 只生成 `RedactionSessionOutput::text()`，全部返回 `&mut Self`：

```rust
impl RedactionSession {
    pub fn literal(&mut self, text: &'static str) -> &mut Self;
    pub fn field(&mut self, field: &str, value: &str) -> &mut Self;
    pub fn value<T: Redact + ?Sized>(&mut self, value: &T) -> &mut Self;
    pub fn argv<F>(&mut self, configure: F) -> &mut Self;
    pub fn env<F>(&mut self, configure: F) -> &mut Self;
    pub fn http<F>(&mut self, configure: F) -> &mut Self;
    pub fn json<F>(&mut self, configure: F) -> &mut Self;
    pub fn uri<F>(&mut self, configure: F) -> &mut Self;
    pub fn process<F>(&mut self, configure: F) -> &mut Self;
}
```

```rust
let output = session
    .literal("request failed: ")
    .field("request_id", request_id)
    .literal(", metadata: ")
    .value(&metadata)
    .http(|http| {
        http.url(request_url);
        http.body(capture, content_type);
    })
    .finish();
```

`literal()` 只接受 `&'static str`，表示程序作者提供的固定字面量，不执行脱敏，
但仍消耗共享输出预算。

### 6.2 单项提取

单项 API 不进入聚合文本，返回不借用 session 的 opaque handle：

```rust
pub struct RedactionHandle {
    transaction_id: TransactionId,
    item_index: usize,
}
```

handle 不实现 `Display`、`AsRef<str>`、`Deref<Target = str>` 或 `ToString`，因此
不能在 `finish()` 前作为文本使用。

```rust
let name = session.redact_field("name", &user.name);
let age = session.redact_field("age", &user.age.to_string());
let website = session.redact_http_url(&user.website);

let output = session.finish();

let message = format!(
    "name: {}, age: {}, website: {}",
    output.resolve(name)?.text(),
    output.resolve(age)?.text(),
    output.resolve(website)?.text(),
);
```

`resolve()` 验证 handle 属于当前 output 的 transaction 且 item 存在：

```rust
pub fn resolve(
    &self,
    handle: RedactionHandle,
) -> Result<&RedactionOutput, RedactionHandleError>;
```

错误仅包括 `DifferentTransaction` 和 `MissingItem`。所有 handle 统一解析为
`RedactionOutput`，不建立异构 result arena。

### 6.3 Format 覆盖

以下六组官方 format 必须同时提供聚合 namespace、单项 handle 和
`Redactor::redact_*` 单次便利方法：

```text
argv
env
http
json
uri
process
```

集合型操作（argv、env、headers）的一次调用对应一个 handle；集合内部逐项计入
结构预算。任意闭包可追加零到多个操作，因此不提供含义模糊的
`redact_http(|http| ...) -> RedactionHandle`。单项方法必须一项对应一个 handle，
例如 `redact_http_url()` 与 `redact_http_body()`。

`Redactor` 可提供单次便利方法，但其实现必须走 session：

```rust
pub fn redact_uri(&self, input: &str) -> RedactionOutput {
    let mut session = self.session();
    let handle = session.redact_uri(input);
    let output = session.finish();
    output.into_resolved(handle)
        .expect("the handle belongs to the completed transaction")
}
```

删除独立 `ArgvRedactor`、`EnvRedactor`、`HttpRedactor`、`JsonRedactor` 和
`UriRedactor` 公共 facade。

## 7. 输出与 summary

```rust
pub struct RedactionSessionOutput {
    transaction_id: TransactionId,
    text: RedactedText,
    summary: RedactionSummary,
    items: Vec<RedactionOutput>,
}

pub struct RedactionOutput {
    text: RedactedText,
    summary: RedactionSummary,
}

pub struct RedactionSummary {
    completion: RedactionCompletion,
    reasons: RedactionReasons,
    usage: RedactionUsage,
}

pub enum RedactionCompletion {
    Complete,
    Truncated,
    Exhausted,
}
```

`RedactionSessionOutput::text()` 是聚合文本，可以为空；session summary 覆盖聚合与
所有 handle 操作；单项 summary 只记录对应操作的增量。

```rust
pub struct RedactionUsage {
    presented_input_bytes: usize,
    inspected_input_bytes: usize,
    output_bytes: usize,
    visited_nodes: usize,
    visited_collection_items: usize,
    max_depth: usize,
    omitted_input_bytes: Option<usize>,
}
```

- `presented_input_bytes` 记录调用者提交的输入长度；
- `inspected_input_bytes` 记录实际允许 parser 或 writer 检查的长度；
- `output_bytes` 记录最终保留且完成字符安全处理的 UTF-8 字节数；
- `omitted_input_bytes` 在源长度未知且已截断时为 `None`；
- session 聚合时计数求和、深度取最大值；存在未知遗漏时聚合遗漏量为 `None`。

completion 只能按 `Complete → Truncated → Exhausted` 单调变化。reason 只累积。
至少支持：`InputLimitReached`、`OutputLimitReached`、
`TraversalLimitReached`、`DepthLimitReached`、`SourceTruncated`、
`InvalidJson`、`InvalidUri`、`InvalidContentType` 和
`UnsupportedContentType`。

`Exhausted` 表示当前操作连安全替代文本也无法完整写入共享输出预算。此前已经成功
暂存的结果仍可发布，但 session 聚合 completion 为 `Exhausted`。

`RedactedText` 继续保留为强类型安全边界：它表示已经完成脱敏、字符安全处理和预算
审核的最终文本。构造函数保持 crate-private，只公开 `as_str()`、`into_string()`、
`Display` 和 `AsRef<str>`。

## 8. 唯一预算与存储

聚合文本、所有 handle 文本、安全替代文本、截断标记以及最终字符转义产生的字节，
共同消耗一份 transaction 输出预算。handle 只引用已生成并计费的 item；
`resolve()` 不复制、不重新计费。

所有输入、输出、节点、集合和深度检查都在 `TransactionState` 中完成。writer 和
adapter 不得拥有第二份预算，不得以 `usize::MAX` 绕过 session limits。

进入 `OutputExhausted` 后，后续操作不得调用 accessor、parser 或 adapter closure，
只维持 aggregate summary。输入必须在 parser 检查内容前完成 admission。

## 9. Panic 原子性

每个可能执行用户代码的入口使用 transaction guard。正常返回时 guard 保留修改；
panic 展开时 guard 废弃整个 transaction、创建新 transaction 并让 panic 继续传播。

若调用者使用 `catch_unwind` 捕获 panic，session 已处于可安全复用的全新 transaction；
失败 transaction 创建的 handle 永久失效。库不把 panic 转换成普通错误，也不要求用户
显式 `reset()`。

## 10. Domain writer 与 derive

公开 writer 的不脱敏路径必须在名称上明确：

```rust
impl RedactionWriter<'_> {
    pub fn literal(&mut self, text: &'static str);
    pub fn unredacted<T: Debug + ?Sized>(&mut self, value: &T);
    pub fn record<F>(&mut self, name: &'static str, configure: F);
    pub fn tuple<F>(&mut self, name: &'static str, configure: F);
    pub fn sequence<F>(&mut self, configure: F);
    pub fn map<F>(&mut self, configure: F);
    pub fn variant<F>(
        &mut self,
        enum_name: &'static str,
        variant_name: &'static str,
        configure: F,
    );
}
```

字段 scope 使用 `unredacted`、`sensitive`、`nested`、`map` 和 `json`；序列和 map
scope 对应使用 `unredacted_item`、`sensitive_item`、`nested_item`、
`unredacted_entry`、`sensitive_entry` 和 `nested_entry`。

derive 映射固定为：

```text
无属性                    → unredacted
#[redact(skip)]           → 不生成访问代码
#[redact(level = "...")] → sensitive
#[redact(nested)]         → nested
#[redact(map)]            → map
#[redact(json)]           → json
```

`unredacted` 完全忽略字段名 policy。`sensitive` 的显式 level 是最低敏感度，policy
只能提高不能降低。`map/json` 是显式选择动态分类，分别按 map key 和 JSON key 应用
policy。`nested` 由子类型自己的标注决定字段行为并共享父 transaction。

所有 `unredacted` API、`Redact` trait 和 derive 文档必须包含醒目警告：未标注字段会
原样输出，框架不根据名称或内容推断敏感性；业务类型新增字段时必须主动审查标注。

```rust
pub trait Redact {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);

    fn redacted(&self) -> RedactionOutput
    where
        Self: Sized,
    {
        Redactor::application_default().redact(self)
    }

    fn redacted_with(&self, redactor: &Redactor) -> RedactionOutput
    where
        Self: Sized,
    {
        redactor.redact(self)
    }
}
```

## 11. 内部依赖边界

```text
policy
  ↓
runtime (budget, buffer, summary, transaction)
  ↓
domain writer
  ↓
format adapters
  ↓
facade (Redactor and public session methods)
```

低层不得依赖高层 facade。adapter 可以使用 crate-private runtime writer，但不能
创建 redactor、budget、summary 或最终输出。公共 `RedactionWriter` 不是
`fmt::Write`/`io::Write`，也不暴露任意动态字符串写入接口。

## 12. 旧 API 立即退场

迁移第一阶段取消公开或删除：

- `RedactionConfig`、`RedactionConfigBuilder`；
- `RedactionEvent`、`DiagnosticLogBuilder`；
- `DomainValueScope`、`DomainValueAdmission`、`DomainTraversalAdmission`；
- `DomainTruncated`；
- lazy `Redacted`、`BoundedRedactedDisplay` 及 `Redacted*Result`；
- 公共 `FieldRedaction` 和执行中间结果；
- `RedactionSessionError`；
- 独立 format redactor；
- `limits`、`model`、`config`、`output` 兼容导出；
- 重复公开路径和 hidden 过渡 builder API。

成熟算法可暂时保留为 crate-private。`rs-redact` 自身在每个任务结束时必须可编译；
下游因旧路径删除而暂时无法编译是预期信号，不得恢复 shim。

## 13. 验证策略

### 13.1 Transaction 与 handle

覆盖链式/逐语句等价、连续复用、finish 自动重置、handle 跨 transaction 失败、panic
回滚、聚合/handle 互不隐式写入以及 finish 前 handle 不可格式化。

### 13.2 共享预算

必须按操作对验证前一操作消耗、后一操作观察剩余预算：`literal → field → value →
JSON → HTTP → URI → argv → env → process`。验证 output exhausted 后不执行 accessor、
parser 或 adapter closure。

### 13.3 Writer 与 derive

分别验证手写和 derive 的 unredacted、skip、四级 sensitivity、nested、map、json、
泛型、enum、Serde、Debug 和 Display。derive 与等价手写实现的 text、summary、usage
必须一致。

### 13.4 Formats

argv、env、http、json、uri、process 各自覆盖正常、非法、上游截断、输入/输出/结构
限制、聚合模式、handle 模式、Redactor 便利方法和跨 format 共享预算。

### 13.5 默认实例

覆盖确定性 Default、应用默认完整快照、替换返回旧值、并发线性化、已有 session 隔离、
`redacted()` 和 `redacted_with()` 的不同来源。

### 13.6 防止测试覆盖再次丢失

每个实现任务先写失败测试并证明旧实现失败。只有替代测试通过后才能删除对应旧测试；
每组删除必须记录行为映射。禁止无映射地批量删除测试。

## 14. 迁移顺序

1. 取消旧公开 API；
2. 重建 policy 与默认实例；
3. 重建 transaction runtime；
4. 重建 domain writer 与 Redactor；
5. 重构 rs-redact-derive；
6. 迁移 argv、env、http、json、uri、process；
7. 依次迁移 rs-value、rs-metadata、rs-config、rs-fs、rs-http、rs-command、
   rs-fs-registry；
8. 删除 crate-private 过渡代码并完成文档与集成验收。

## 15. 完成标准

- 旧公开符号和兼容模块在所有生产代码中不存在；
- 所有 domain、derive 和 format 路径使用同一个 `TransactionState`；
- 不存在空预算函数或通过 `usize::MAX` 绕过 session 的执行路径；
- 聚合和 handle 文本共同受一个输出预算约束；
- summary 与实际执行一致，不由 facade 伪造；
- panic 回滚测试、跨 format 预算测试、derive parity 测试通过；
- rs-redact 和 rs-redact-derive 全 feature/trybuild 测试通过；
- 所有直接下游完成破坏性迁移并通过测试；
- rustfmt、Clippy、Rustdoc、style check 和 fuzz 验证通过；
- README、中文 README、双语 user guide 与最终 API 一致。

