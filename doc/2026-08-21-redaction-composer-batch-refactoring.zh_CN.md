# rs-redact 文本组合器与批量脱敏 API 重构方案

日期：2026-08-21

## 1. 文档状态

本文定义 `qubit-redact` 0.5.0 在发布前完成的破坏性 API 重构。它取代
`doc/2026-08-19-rs-redact-transactional-redesign-design.md` 中把聚合文本与独立 item
放入同一个 `RedactionSession` 的设计。旧文档中关于 policy、字段解析、掩码、资源预算、
格式解析、domain writer、summary 与安全发布的设计继续有效；与本文冲突的 session、handle
和 output 设计以本文为准。

本次迁移允许破坏性变更，不保留 deprecated alias、旧方法转发或兼容 facade。

## 2. 问题陈述

当前 `RedactionSession` 同时承担两个不同场景：

1. `literal()`、`field()`、`value()`、`http()` 等调用按顺序追加片段，最终形成一段文本；
2. `redact_http_url()`、`redact_json()`、`redact_value()` 等调用产生彼此独立的结果，只共享
   policy、预算和原子发布边界。

这导致以下问题：

- `finish()` 返回的 `RedactionSessionOutput::text()` 只包含聚合调用，独立 item 隐藏在另一组
  存储中；
- `session.http(...)` 与 `session.redact_http_url(...)` 名字接近，返回值和数据流却完全不同；
- `RedactionSessionOutput` 同时表示一段最终文本和一批可解析结果；
- 共享底层预算被误表达为共享公共对象模型；
- 可复用 session 在每次 `finish(&mut self)` 后静默重置 transaction，使一份 session、一次操作
  和一份输出之间缺少一一对应关系。

共享 policy、预算和底层格式算法是实现约束，不应迫使两个使用场景共用一个公共类型。

## 3. 已确认的设计决策

本次重构采用以下最终命名：

| 职责 | 类型 |
| --- | --- |
| 按顺序组合一段安全文本 | `RedactedTextComposer` |
| 一次文本组合的最终结果 | `RedactionTextOutput` |
| 在共享预算下处理多个独立 item | `RedactionBatch` |
| 一批 item 的最终结果 | `RedactionBatchOutput` |
| 引用 batch 中一个未发布 item | `RedactionBatchHandle` |
| 报告 handle 解析错误 | `RedactionBatchHandleError` |

两种入口均由 `Redactor` 创建：

```rust
impl Redactor {
    pub fn text_composer(&self) -> RedactedTextComposer;
    pub fn batch(&self) -> RedactionBatch;
}
```

两种对象均为单次使用，`finish(self)` 消耗自身。`Redactor` 只需为它们克隆一份
`Arc<RedactionPolicy>`，不需要为复用暴露额外生命周期语义。

## 4. RedactedTextComposer

### 4.1 职责

`RedactedTextComposer` 只负责按调用顺序组合一份最终安全文本。它与结果的消费位置无关：同一份
`RedactionTextOutput` 可以用于日志、错误信息、遥测文本字段或其他字符串接收方。

它不负责构造结构化遥测事件，也不产生 handle。

### 4.2 消费式链式 API

所有组合方法取得 `self` 并返回 `Self`，保证 `finish(self)` 仍可位于同一条调用链末尾：

```rust
impl RedactedTextComposer {
    pub fn literal(self, text: &'static str) -> Self;
    pub fn field(self, field: &str, value: &str) -> Self;
    pub fn value<T: Redact + ?Sized>(self, value: &T) -> Self;

    pub fn argv<F>(self, configure: F) -> Self;
    pub fn env<F>(self, configure: F) -> Self;
    pub fn process<F>(self, configure: F) -> Self;
    pub fn json<F>(self, configure: F) -> Self;
    pub fn http<F>(self, configure: F) -> Self;
    pub fn uri<F>(self, configure: F) -> Self;

    pub fn finish(self) -> RedactionTextOutput;
}
```

代表性用法：

```rust
let output = redactor
    .text_composer()
    .literal("request failed: ")
    .field("request_id", "req-42")
    .http(|http| {
        http.url(raw_url);
    })
    .finish();
```

`literal()` 继续只接受 `&'static str`。运行时字符串必须经过字段、domain 或格式 API，不能借
`literal()` 绕过脱敏决策。

### 4.3 Format writer 边界

`ArgvRedactionWriter`、`EnvRedactionWriter`、`ProcessRedactionWriter`、
`JsonRedactionWriter`、`HttpRedactionWriter` 和 `UriRedactionWriter` 只作为 composer namespace
闭包中的借用 facade。它们的公开方法只追加文本并返回 `&mut Self`；现有返回 handle 的
`redact_*` 方法移除或收为 crate-private，避免在 writer 层重新混合两种模型。

## 5. RedactionBatch

### 5.1 职责

`RedactionBatch` 在同一 policy 快照和资源预算下处理多个独立输出项。batch 可以是异构的；
一个 domain object、一个 JSON 文档、一组 HTTP headers、一个 URL、一个 HTTP body、一个 URI、
一组 argv 或环境变量都可以各自构成一个逻辑 item。

集合输入的一次调用只产生一个 handle。例如一份 `HeaderMap` 是一个 batch item；集合内部每个
header 仍分别计入结构和集合预算。

### 5.2 可变添加 API

batch 方法借用 `&mut self` 并返回 handle：

```rust
impl RedactionBatch {
    pub fn redact_field(&mut self, field: &str, value: &str) -> RedactionBatchHandle;
    pub fn redact_value<T: Redact + ?Sized>(&mut self, value: &T) -> RedactionBatchHandle;
    pub fn redact_argv<'a, I>(&mut self, items: I) -> RedactionBatchHandle;
    pub fn redact_env(&mut self, name: &str, value: &str) -> RedactionBatchHandle;
    pub fn redact_env_pairs<'a, I>(&mut self, pairs: I) -> RedactionBatchHandle;
    pub fn redact_process<'a, 'b, A, E>(
        &mut self,
        program: &'a OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionBatchHandle;
    pub fn redact_json(&mut self, text: &str) -> RedactionBatchHandle;
    pub fn redact_http_url(&mut self, value: &str) -> RedactionBatchHandle;
    pub fn redact_http_headers(&mut self, headers: &HeaderMap) -> RedactionBatchHandle;
    pub fn redact_http_body(
        &mut self,
        capture: BodyCapture<'_>,
        content_type: Option<&HeaderValue>,
    ) -> RedactionBatchHandle;
    pub fn redact_uri(&mut self, value: &str) -> RedactionBatchHandle;

    pub fn finish(self) -> RedactionBatchOutput;
}
```

泛型约束与 feature gate 沿用现有对应 API。上面的签名用于固定命名和返回关系，不省略现有
`ExactSizeIterator` 等资源记账所需约束。

代表性用法：

```rust
let mut batch = redactor.batch();

let user = batch.redact_value(&user);
let payload = batch.redact_json(json);
let headers = batch.redact_http_headers(&headers);
let url = batch.redact_http_url(url);

let output = batch.finish();
let safe_user = output.resolve(user)?;
let safe_payload = output.resolve(payload)?;
let safe_headers = output.resolve(headers)?;
let safe_url = output.resolve(url)?;
```

batch 不提供 `literal()`，也不提供任何把 item 拼接为单一文本的 API。

## 6. 输出与 handle

### 6.1 单文本输出

```rust
pub struct RedactionTextOutput {
    text: RedactedText,
    summary: RedactionSummary,
}

impl RedactionTextOutput {
    pub fn text(&self) -> &RedactedText;
    pub fn summary(&self) -> &RedactionSummary;
}
```

`RedactionTextOutput` 同时用于 composer 的最终输出、batch 中的单个 item，以及
`Redactor::redact_*()` 的一次性输出。

### 6.2 Batch 输出

```rust
pub struct RedactionBatchOutput {
    batch_id: BatchId,
    items: Vec<RedactionTextOutput>,
    summary: RedactionSummary,
}

impl RedactionBatchOutput {
    pub fn summary(&self) -> &RedactionSummary;
    pub fn resolve(
        &self,
        handle: RedactionBatchHandle,
    ) -> Result<&RedactionTextOutput, RedactionBatchHandleError>;
    pub fn into_resolved(
        self,
        handle: RedactionBatchHandle,
    ) -> Result<RedactionTextOutput, RedactionBatchHandleError>;
}
```

`RedactionBatchOutput` 不提供 `text()`，因为 batch 没有聚合文本。`resolve()` 不复制文本，也不
重新计费。

空 composer 发布 complete 的空文本；空 batch 发布不含 item、summary 为 complete 的 batch
output。空操作仍遵循单次使用的 `finish(self)` 生命周期。

### 6.3 Handle 约束

`RedactionBatchHandle` 保存不可伪造的 batch identity 和 item index。它不实现 `Display`、
`AsRef<str>`、`Deref<Target = str>` 或 `ToString`，不能在 `finish()` 前暴露脱敏中间文本。

```rust
pub enum RedactionBatchHandleError {
    DifferentBatch,
    MissingItem,
}
```

`DifferentBatch` 表示 handle 与 output 的 batch identity 不同；`MissingItem` 只表示同一 batch
identity 下索引无效。

## 7. Redactor 一次性 API

`Redactor::redact_*()` 继续作为处理一个值的便利入口，但统一返回 `RedactionTextOutput`：

```rust
impl Redactor {
    pub fn redact<T: Redact + ?Sized>(&self, value: &T) -> RedactionTextOutput;
    pub fn redact_field(&self, field: &str, value: &str) -> RedactionTextOutput;
    pub fn redact_argv<'a, I>(&self, items: I) -> RedactionTextOutput;
    pub fn redact_env(&self, name: &str, value: &str) -> RedactionTextOutput;
    pub fn redact_env_pairs<'a, I>(&self, pairs: I) -> RedactionTextOutput;
    pub fn redact_process<'a, 'b, A, E>(/* ... */) -> RedactionTextOutput;
    pub fn redact_json(&self, text: &str) -> RedactionTextOutput;
    pub fn redact_http_url(&self, value: &str) -> RedactionTextOutput;
    pub fn redact_http_headers(&self, headers: &HeaderMap) -> RedactionTextOutput;
    pub fn redact_http_body(/* ... */) -> RedactionTextOutput;
    pub fn redact_uri(&self, value: &str) -> RedactionTextOutput;
}
```

这些方法内部必须复用 batch 的单项路径，不能维护第二套格式脱敏、预算或 summary 实现。

## 8. 内部运行时重构

### 8.1 共享与分离

公共类型分离不意味着复制底层算法。落地实现将 `TransactionState` 组织为：

```text
RedactionRuntime
├── Arc<RedactionPolicy>
├── RedactionBudget
├── SummaryBuilder
├── TransactionPhase
└── domain/format 临时 frame

TransactionState
├── RedactionRuntime
└── PublicationBuffer::{Text(TextOutputBuffer), Batch(BatchOutputBuffer)}
```

`RedactionRuntime` 只负责 policy、admission、预算、summary、掩码选择和格式/domain 执行上下文；
它不决定最终结果是一段文本还是一批 item。

每个 `TransactionState` 恰好选择一个发布缓冲区：composer 使用 `TextOutputBuffer`，batch 使用
`BatchOutputBuffer`。crate-private 的 `RedactionSession` 只作为该状态的运行时 façade，用于复用
格式 writer 的借用边界；它按创建入口固定为 text 或 batch，既不公开导出，也不同时持有 aggregate
与 item 输出。格式算法先产生内部 `RenderedOperation`，再由当前公共模型提交到对应缓冲区。

### 8.2 唯一预算

- composer 的输入、输出、节点、集合和深度预算覆盖整段最终文本；
- batch 的相同预算覆盖全部 item 之和；
- 每个 batch item 保留自己的增量 summary，但不拥有第二份预算；
- 安全替代文本、截断标记和控制字符转义后的最终字节都计入输出预算；
- 进入 `OutputExhausted` 后，不再检查后续输入或调用 parser；batch 后续调用返回 canonical
  exhausted item 的 handle；composer 后续链式操作只累计可观察的 exhausted summary；
- 此规则同样适用于由批量 facade 提供的便捷 format 方法；它们必须直接走 batch item 路径，不能
  借 aggregate namespace 回调间接取得 handle；
- handle 解析不复制、不重新脱敏，也不重新计费。

### 8.3 发布与 panic

`finish(self)` 是唯一发布边界。构造中的 composer、batch、format writer 和 handle 均不得通过
`Debug`、`Display` 或字符串引用暴露输入或中间文本。

composer 方法消费 `self`；用户回调 panic 时，整个未发布 composer 随展开过程被丢弃。

batch 的 `value()` 等可能执行用户代码的方法继续使用 transaction guard。panic 时废弃整批
未发布状态、安装新的空 batch identity 并继续展开 panic。若调用方用 `catch_unwind` 捕获 panic，
batch 仍处于安全的空状态；panic 前产生的 handle 不再属于之后发布的 output。

## 9. Summary 与错误模型

`RedactionCompletion` 继续按 `Complete -> Truncated -> Exhausted` 单调恶化，reason 只累积，usage
采用字节与结构计数求和、最大深度取最大值的合并方式。

- composer summary 描述整段文本；
- batch summary 描述全部 item 的总消耗和最严重完成状态；
- item summary 只描述该 item 的增量；
- 非法 JSON/URI、上游截断、不支持的 content type 和预算不足均是安全输出状态，不是
  `finish()` 错误；
- policy 构建继续使用 `PolicyError`；
- 只有 handle 使用错误返回 `RedactionBatchHandleError`。

## 10. 破坏性迁移映射

| 旧 API | 新 API |
| --- | --- |
| `Redactor::session()` | `Redactor::text_composer()` 或 `Redactor::batch()` |
| `RedactionSession` 聚合方法 | `RedactedTextComposer` 消费式链式方法 |
| `RedactionSession::redact_*()` | `RedactionBatch::redact_*()` 方法 |
| `RedactionSession::finish()` 聚合结果 | `RedactedTextComposer::finish()` |
| `RedactionSession::finish()` item 结果 | `RedactionBatch::finish()` |
| `RedactionOutput` | `RedactionTextOutput` |
| `RedactionSessionOutput` | `RedactionBatchOutput`；聚合场景无对应容器 |
| `RedactionHandle` | `RedactionBatchHandle` |
| `RedactionHandleError` | `RedactionBatchHandleError` |
| `DifferentTransaction` | `DifferentBatch` |

以下旧公共符号直接删除，不提供 alias：

- `RedactionSession`；
- `RedactionSessionOutput`；
- `RedactionOutput`；
- `RedactionHandle`；
- `RedactionHandleError`；
- `Redactor::session()`；
- format writer 上公开的 handle 生成方法。

## 11. 实施顺序

1. 先增加公共 API 编译测试，固定新类型、方法签名、feature gate 和单次使用语义。
2. 将 `RedactionOutput` 重命名为 `RedactionTextOutput`，更新不依赖 session 的调用点。
3. 提取不拥有发布模式的 `RedactionRuntime`，保留现有预算和 summary 行为测试。
4. 实现 `RedactedTextComposer`、消费式链式方法和 `TextOutputBuffer`。
5. 实现 `RedactionBatch`、batch item staging、identity、handle 和 `RedactionBatchOutput`。
6. 将所有格式 writer 收窄为 composer-only facade；把单项格式入口移到 batch。
7. 让 `Redactor::redact_*()` 统一复用 batch 单项路径。
8. 更新 domain writer、panic guard 和 derive 集成。
9. 删除旧 session、旧 output、旧 handle 和所有兼容路径。
10. 迁移 README、用户指南、crate-level docs、fuzz targets、benches 与直接下游仓库。

迁移期间不保留同时支持新旧 API 的中间公共状态。每一步可以在内部临时适配，但合入前公共导出
必须只包含新模型。

## 12. 验证矩阵

### 12.1 公共 API

- composer 支持完整链式调用并由 `finish(self)` 消耗；
- batch 通过 `&mut self` 返回 handle，并由 `finish(self)` 消耗；
- composer 不公开 batch 方法，batch 不公开组合方法；
- `RedactionBatchOutput` 没有 `text()`；
- `RedactionTextOutput` 没有 handle 解析方法；
- 旧公共符号和兼容 alias 均不可导入；
- JSON、HTTP、URI API 只在相应 feature 启用时出现。

### 12.2 行为与资源

- composer 输出顺序与调用顺序一致；
- 异构 batch item 保持独立文本和增量 summary；
- batch summary 的输出字节等于已发布 item 输出字节之和；
- composer 与 batch 各自只有一份输入、输出、结构和深度预算；
- 精确用完输出预算仍可得到完整当前结果，后续操作进入 exhausted；
- exhausted 后不访问输入、不运行 parser 和用户 adapter；
- UTF-8 边界、控制字符转义和安全替代文本全部受预算约束。

### 12.3 Handle 与 panic

- 同 batch handle 可解析；
- 跨 batch handle 返回 `DifferentBatch`；
- 无效同 batch 索引返回 `MissingItem`；
- handle 在 `finish()` 前不能转成文本；
- domain 或 adapter panic 不发布半成品；
- batch panic 回滚后旧 handle 失效；
- composer panic 时整个 composer 被丢弃。

### 12.4 格式覆盖

字段、domain、argv、env、process、JSON、HTTP URL、HTTP headers、HTTP body 和 URI 必须分别覆盖：

- composer 路径；
- batch 路径；
- `Redactor::redact_*()` 一次性路径；
- 输入、输出和结构预算；
- 完整、截断、耗尽及格式错误状态。

## 13. 完成标准

重构完成必须同时满足：

1. 公共 API 只表达 composer、batch 和一次性 redactor 三层模型；
2. 聚合文本与独立 item 不再出现在同一个公共类型中；
3. 所有格式和 domain 路径共享同一套 policy、预算、summary 与安全发布实现；
4. 不存在旧 session/output/handle 的兼容导出；
5. README、中文用户指南、crate docs 和核心设计文档只使用新术语；历史迁移说明以及验证已删除
   符号不可导入的 `compile_fail` 示例除外；
6. 默认 feature、`--all-features`、doctest、fuzz 和 CI 检查全部通过；
7. 直接下游不再引用旧 API。

## 14. 非目标

- 本次不新增自动秘密内容检测；
- 不把结构化遥测 schema 建模为本库类型；
- 不新增跨 composer 或跨 batch 的共享预算；
- 不提供流式发布或在 `finish()` 前读取中间文本；
- 不新增 JSON AST 专用公共输入；当前 `json(&str)` 将一个 JSON 文档作为一个逻辑 item；
- 不为 0.5.0 保留旧 API 的兼容周期。
