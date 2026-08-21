# rs-redact 核心架构设计

版本目标：`qubit-redact` 0.5.0

更新日期：2026-08-21

## 1. 文档定位

本文是 `rs-redact` 的核心设计文档，描述 0.5.0 完成本轮 API 重构后的目标架构。它覆盖公共对象
模型、policy、运行时、输出、domain object、derive、格式适配、安全边界、资源约束、错误模型和
测试策略。

历史设计文档用于保留决策演进过程；当历史文档与本文冲突时，以本文为准。本轮 composer/batch
拆分的迁移细节见
[`2026-08-21-redaction-composer-batch-refactoring.zh_CN.md`](2026-08-21-redaction-composer-batch-refactoring.zh_CN.md)。

本文描述当前公开 API 的设计。运行时可以保留不向调用方公开的实现辅助类型，但不得以兼容层
重新导出旧的 session、handle 或 output API。

## 2. 项目目标与边界

`qubit-redact` 将字段、Rust domain object、命令数据、JSON、HTTP 和 URI 转换为有资源上限、
UTF-8 有效、控制字符安全并可写入日志或遥测系统的文本。

核心目标是：

1. 由不可变 policy 统一决定字段分类、掩码、格式行为和资源上限；
2. 在发布前私有保存脱敏结果，避免中间状态泄露；
3. 对一段组合文本或一批独立结果执行统一预算记账；
4. 在输入异常或资源不足时失败关闭，并用机器可读 summary 描述降级；
5. 允许 domain 类型显式描述其安全呈现方式；
6. 为 argv、env、process、JSON、HTTP 和 URI 提供一致的格式适配层；
7. 保持默认行为确定、policy 快照不可变、并发共享成本低。

本项目明确不做以下事情：

- 不根据任意值内容猜测秘密；
- 不替业务所有者决定未标注字段是否敏感；
- 不构造日志事件或遥测事件 schema；
- 不保证上游在输入交给本库前没有泄露；
- 不在 `finish()` 前发布中间文本；
- 不把资源耗尽转换成普通业务错误。

## 3. 仓库与 crate 边界

整个设计由两个可发布 crate 协作完成：

- `qubit-redact`：运行时、policy、输出类型、domain traits 和格式适配；
- `qubit-redact-derive`：`#[derive(Redact)]` 过程宏及其编译期校验。

derive crate 只生成对运行时公共 domain API 的调用，不复制字段解析、掩码、预算或格式算法。
运行时 crate 不依赖 derive crate；应用可选择手写 trait 实现或使用 derive。

`qubit-redact` 的 feature 边界如下：

| Feature | 能力 |
| --- | --- |
| 默认 | 字段、domain、argv、env、process、policy、运行时和输出 |
| `serde` | 与脱敏序列化相关的 trait 支持 |
| `json` | JSON 文档解析、结构预算和 JSON domain 字段 |
| `http` | HTTP URL、headers、body；同时启用 `json` |
| `uri` | 通用 URI 解析与组件策略 |

feature 关闭时，相应公共模块、builder namespace 和方法必须在编译期不可见，而不是运行期报错。

## 4. 总体架构

```text
RedactionPolicy ── Arc immutable snapshot ──> Redactor
                                                │
                    ┌───────────────────────────┼───────────────────────────┐
                    │                           │                           │
                    ▼                           ▼                           ▼
          RedactedTextComposer           RedactionBatch            redact_* convenience
          one ordered text               independent items          one text output
                    │                           │                           │
                    └──────────────┬────────────┴───────────────────────────┘
                                   ▼
                         private RedactionRuntime
                    policy + budget + summary + admission
                                   │
            ┌──────────┬───────────┼──────────┬──────────┬──────────┐
            ▼          ▼           ▼          ▼          ▼          ▼
          domain      argv       env/process  JSON       HTTP       URI
                                   │
                                   ▼
                  RedactionTextOutput / RedactionBatchOutput
```

公共对象模型按输出形态分离；底层运行时和格式算法按安全规则共享。公共层不暴露 transaction
实现细节。

## 5. 公共对象模型

### 5.1 RedactionPolicy

`RedactionPolicy` 是完整、不可变、可共享的规则快照，包含：

- 应用字段规则与可选安全 floor；
- 四级 sensitivity 对应的掩码策略；
- 输入、输出、domain 和 JSON 结构上限；
- HTTP 各上下文规则与路径、文本 body 行为；
- URI path 与 fragment 行为。

policy 构建完成后不再修改。需要变更时，通过 `to_builder()` 基于旧快照构建新快照。

### 5.2 Redactor

`Redactor` 是持有 `Arc<RedactionPolicy>` 的廉价可克隆 facade。它负责：

- 创建 `RedactedTextComposer`；
- 创建 `RedactionBatch`；
- 提供处理一个值的 `redact_*()` 便利方法；
- 暴露确定性的 `standard()`、安全收紧的 `strict()` 和进程级应用默认快照。

`Redactor` 本身不持有可变预算或未发布输出，可在线程间共享。

### 5.3 RedactedTextComposer

`RedactedTextComposer` 表示一次“组合一段安全文本”的工作。它通过消费式链式 API 追加可信程序
字面量、字段、domain value 和各格式内容，最终由 `finish(self)` 产生一个
`RedactionTextOutput`。

```rust
let output = redactor
    .text_composer()
    .literal("request failed: ")
    .field("request_id", request_id)
    .finish();
```

composer 只生成一段文本，不产生 handle，也不承担结构化事件建模。

### 5.4 RedactionBatch

`RedactionBatch` 表示一次“在共享预算下处理多个独立值”的工作。每次添加操作返回一个
`RedactionBatchHandle`，`finish(self)` 原子发布 `RedactionBatchOutput`。

```rust
let mut batch = redactor.batch();
let user = batch.redact_value(&user);
let url = batch.redact_http_url(raw_url);
let headers = batch.redact_http_headers(&headers);

let output = batch.finish();
let safe_user = output.resolve(user)?;
let safe_url = output.resolve(url)?;
let safe_headers = output.resolve(headers)?;
```

batch 可以包含异构 item。一个集合型输入仍是一个逻辑 item，但集合内部逐项消耗结构预算。

### 5.5 一次性入口

`Redactor::redact()`、`redact_field()`、`redact_json()`、`redact_http_url()` 等方法用于只需要
一个结果的场景，统一返回 `RedactionTextOutput`。它们内部复用 batch 的单 item 路径，不维护
第二套实现。

## 6. Policy 模块

### 6.1 构建与事务验证

`RedactionPolicy::builder()` 返回消费式 builder。`fields()`、`masking()`、`limits()`、
`http()` 和 `uri()` namespace 在临时 draft 中执行闭包；闭包结束后统一验证，验证成功才整体
应用。无效配置返回 `PolicyError`，不能在 builder 中留下半次修改。

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
    .build()?;
```

### 6.2 字段规则

字段分类支持：

- 显式 sensitive rule；
- 显式 allow rule；
- exact 或 token-suffix 名称匹配；
- unknown field fallback；
- 内置 sensitive presets；
- 独立安全 floor。

字段名先按规范化候选进行匹配。应用层 allow 只影响应用层决策，不能绕过 floor。应用规则与
floor 都命中 sensitivity 时取更强等级。floor 不提供 allow bypass，因此是不可被普通业务规则
削弱的最低保护。

`classify_field()` 只解释应用层匹配结果；最终是否敏感必须使用包含 floor 的解析路径。

### 6.3 敏感等级与掩码

敏感等级按以下顺序增强：

```text
Low < Medium < High < Secret
```

每个等级映射到一个 `MaskPolicy`：

- `Fixed`：固定替换；
- `PreserveEdges`：保留 Unicode scalar 前后边缘；
- `PreserveSuffix`：只保留末尾；
- `Empty`：删除非空值。

当原值内容不可安全检查时，必须使用 opaque mask，不能从 edge-preserving policy 中保留原值片段。
所有 mask 都有受输出字节上限约束的写入路径。

### 6.4 Standard、strict 与默认实例

- `RedactionPolicy::default()` 与 `Redactor::default()` 必须确定性等价于 standard；
- `strict()` 用于不可信边界，对未知标量采用更保守策略，并收紧可能包含秘密的格式组件；
- `Redactor::application_default()` 返回进程级完整快照；
- `replace_application_default()` 在线性化写锁下替换完整 redactor，并返回旧值；
- 已创建的 redactor、composer 和 batch 保留原快照，不受之后替换影响；
- `Redact::redacted()` 使用 application default；显式 `redacted_with()` 只使用传入 redactor。

全局槽只保存不可变 redactor 快照，不保存活动预算或输出。

## 7. 私有运行时与事务模型

### 7.1 RedactionRuntime

crate-private 的 `RedactionRuntime` 统一拥有：

- `Arc<RedactionPolicy>`；
- `RedactionBudget`；
- 聚合 `SummaryBuilder`；
- `TransactionPhase`；
- domain traversal context；
- parser、writer 和格式操作使用的临时 frame。

它负责 admission、字段解析、掩码选择、输入记账、输出记账、结构遍历和 summary 合并，但不决定
结果存入单文本还是 batch item。

### 7.2 发布存储

composer 和 batch 使用不同的私有发布容器：

- composer 的 `TextOutputBuffer` 只保存有序文本片段；
- batch 保存 item ranges、item summary 和 batch identity；
- 两者共享 `RenderedOperation` 等内部安全结果表示；
- 最终发布移动已有存储，不重新脱敏或重新计费。

不得保留一个在公共语义上同时容纳 aggregate 和 item 的输出对象。

### 7.3 生命周期

composer 与 batch 均为单次使用：

```rust
pub fn finish(self) -> RedactionTextOutput;
pub fn finish(self) -> RedactionBatchOutput;
```

一个对象、一份预算和一次发布严格一一对应。完成下一次工作时从 `Redactor` 创建新对象。
空 composer 发布 complete 的空文本；空 batch 发布 complete 且不含 item 的 batch output。

### 7.4 Panic 原子性

可能执行用户代码的路径必须保证原子性：

- composer 的消费式调用 panic 时，整个未发布对象被丢弃；
- batch 的用户回调或 domain traversal panic 时，guard 废弃整批状态、更新 identity，并继续展开
  panic；
- 不把 panic 转换为普通 error；
- `catch_unwind` 后不能发布 panic 前的半成品；
- 回滚前生成的 batch handle 永久失效。

## 8. 资源预算

### 8.1 预算维度

每个 composer 或 batch 只拥有一组限制：

- 最大提交/检查输入字节；
- 最大最终输出字节；
- domain 最大深度；
- 最大访问节点；
- 单集合最大 sequence item 和 map entry；
- 最大 key 字节；
- 启用 JSON 时的 JSON value 结构上限。

### 8.2 记账规则

- `presented_input_bytes` 记录调用方呈现的输入；
- `inspected_input_bytes` 记录 parser 或 writer 实际获准检查的输入；
- `output_bytes` 记录最终保留且完成字符安全处理的 UTF-8 字节；
- `visited_nodes` 与 `visited_collection_items` 记录实际获准访问的结构；
- `max_depth` 取整个操作观察到的最大深度；
- `omitted_input_bytes` 在源总长度已知时累计，任一来源未知则合并结果为 `None`。

composer 的预算覆盖完整组合文本；batch 的预算覆盖全部 item 之和。batch item summary 是本 item
增量，不是独立预算。

### 8.3 Exhaustion

`TransactionPhase` 至少包含 `Active` 与 `OutputExhausted`。完整写入恰好用完输出预算时，当前结果
仍为 complete，但之后不再检查任何输入。连安全替代内容都无法完整写入时，completion 为
`Exhausted`。

进入 exhausted 后：

- 不调用 accessor、parser、format adapter 或用户回调；
- composer 只累计后续写入尝试对应的 summary；
- batch 为后续调用返回 canonical exhausted item 的 handle；
- 先前完整暂存的内容仍可在 `finish()` 时发布。

## 9. 输出、安全文本与 summary

### 9.1 RedactedText

`RedactedText` 是最终安全文本的强类型边界，表示文本已经完成：

- policy 脱敏；
- 资源预算审核；
- UTF-8 边界处理；
- 日志控制字符转义。

构造函数保持 crate-private。公开只读/消费能力包括 `as_str()`、`AsRef<str>`、`Display` 和
`into_string()`。类型名称不表示业务字段本身一定被正确标注；调用者仍需遵守 policy 与 domain
标注安全边界。

### 9.2 RedactionTextOutput

`RedactionTextOutput` 包含一份 `RedactedText` 和一份 `RedactionSummary`。它是所有最终单文本
结果的统一类型，包括 composer 输出、batch item 和一次性 redactor 输出。

### 9.3 RedactionBatchOutput

`RedactionBatchOutput` 包含 batch identity、item 列表和整批 summary。它没有 `text()`；调用方
必须用 `RedactionBatchHandle` 解析具体 item。

`RedactionBatchHandle` 是不透明能力 token，不能转为字符串。解析错误只有：

- `DifferentBatch`：handle 属于另一批；
- `MissingItem`：同一 identity 下索引无效。

### 9.4 Summary

`RedactionSummary` 包含：

- `RedactionCompletion`：`Complete`、`Truncated`、`Exhausted`；
- `RedactionReasons`：紧凑 reason 集合；
- `RedactionUsage`：输入、输出与结构用量。

completion 只能单调恶化，reason 只累积。核心 reason 包括：

- `InputLimitReached`；
- `OutputLimitReached`；
- `TraversalLimitReached`；
- `DepthLimitReached`；
- `SourceTruncated`；
- `InvalidJson`；
- `InvalidUri`；
- `InvalidContentType`；
- `UnsupportedContentType`。

应用必须检查 summary，而不是解析替换文本推断降级原因。

## 10. Domain object 模块

### 10.1 不可变呈现

`Redact` 描述一个类型如何将自身写入 `RedactionWriter`：

```rust
pub trait Redact {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);
}
```

`RedactionWriter` 及其 `RedactionFields`、`RedactionItems`、`RedactionEntries` 借用当前私有运行时，
不创建 policy、预算或最终输出。它们分别表达 record/tuple、sequence 和 map 的结构边界。

主要字段模式为：

- `unredacted`：明确直通，绕过字段名 policy；
- `sensitive`：指定最低 sensitivity，policy 只能增强；
- `nested`：委托给另一个 `Redact`；
- `map`：按运行时 map key 应用字段 policy；
- `json`：按 JSON object key 应用 JSON/字段 policy；
- `skip`：不访问也不输出。

`unredacted` 是信任边界。框架不会根据字段名或内容推翻显式直通决定。

### 10.2 原地修改

`RedactMut`、`RedactValueMut` 和 `RedactMapValueMut` 支持在所有权与类型条件允许时原地替换敏感
内容。它们与文本呈现共享分类与掩码语义，但不是发布 `RedactedText` 的替代路径。

包含无法安全原地替换的借用字段时，类型必须只实现不可变脱敏，derive 侧通过
`#[redact(no_mut)]` 明确关闭 `RedactMut` 生成。

## 11. Derive 模块

`qubit-redact-derive` 为 struct 和 enum 生成 `Redact`，默认同时生成可行的 `RedactMut`。字段模式
映射如下：

| 属性 | 语义 |
| --- | --- |
| 无属性 | 按普通 `Debug` 明确直通 |
| `#[redact(plain)]` | 显式直通 |
| `#[redact(level = "...")]` | 以指定 sensitivity 为最低等级掩码 |
| `#[redact(skip)]` | 不访问、不输出 |
| `#[redact(nested)]` | 委托嵌套类型 |
| `#[redact(map)]` | 按 map key 动态分类 |
| `#[redact(json)]` | 解析字符串 JSON 并按 object key 分类 |

容器级能力包括：

- `debug`：生成脱敏 `Debug`；
- `display`：生成脱敏 `Display`；
- `serde`：生成脱敏序列化支持；
- `no_mut`：不生成原地脱敏实现；
- `require_explicit`：要求每个字段显式选择模式。

未标注字段默认直通是有意设计，不是自动隐私保证。安全敏感类型应优先使用
`#[redact(require_explicit)]` 作为编译期审查辅助。新增业务字段时必须重新审查标注。

derive 需要正确处理 crate rename、泛型 bounds、tuple/unit 类型、enum tagging 和 serde 属性，错误
必须在编译期给出针对性诊断。

## 12. 格式适配模块

所有格式适配器遵守同一结构：

1. 在读取或解析内容前完成 input/structure admission；
2. 使用当前 `RedactionRuntime` 的 policy、预算和 summary；
3. 产生内部 `RenderedOperation`；
4. 由 composer 追加到文本，或由 batch 暂存为一个 item；
5. 不拥有第二份预算和最终输出类型。

### 12.1 argv

`ArgvItem` 携带 `OsStr` 和可选的调用方权威 sensitivity。显式 sensitive item 整体掩码且不解释为
命令语法；plain item 可在 heuristic 模式下识别参数名与关联值。非 UTF-8 输入必须安全降级，
不能通过调试格式泄露原字节。

一组 argv 在 batch 中是一个 item，集合元素分别计入结构预算。

### 12.2 env

环境变量按名称应用字段规则。单个 name/value pair 或一组 OS 字符串 pairs 都可以作为完整操作；
集合版本在 batch 中只产生一个 handle。非 UTF-8 name/value 必须使用安全表示。

### 12.3 process

process 组合 program、arguments 和 environment variables，并复用 argv 与 env 的底层规则。
program、参数和变量共享当前操作预算，不得各自创建子预算。

### 12.4 JSON

JSON adapter 接受文本 JSON 文档，按 object key 递归应用字段规则，并受 JSON/domain 结构上限和
总输入输出预算约束。unkeyed scalar 的处理由 `UnkeyedJsonValuePolicy` 决定。

无效 JSON 不返回 parser error 给调用方；它产生安全替代文本并记录 `InvalidJson`。一个 JSON 文档
在 batch 中是一个逻辑 item。本版本不提供独立 JSON AST 公共输入 API。

### 12.5 HTTP

HTTP adapter 将 URL、headers 和 body 视为不同原子操作：

- URL：userinfo 必须安全处理，query 按 query rules，path 由 `UrlPathPolicy` 控制；
- headers：按 header rules 逐字段处理，整份 `HeaderMap` 在 batch 中是一个 item；
- body：通过 `BodyCapture` 携带捕获字节及上游截断事实，根据 content type 分派 JSON、form、
  multipart 或 opaque text 处理；
- form query/body 使用对应上下文规则；
- `TextBodyPolicy::Redact` 是 opaque text body 的安全默认值。

`BodyCapture` 必须如实区分完整输入、已知总长度的截断输入和未知遗漏长度的截断输入。其 `Debug`
只显示安全元数据，不显示 body 字节。

非法或不支持的 content type 通过 summary 表达。multipart 的边界、header 和嵌套内容也受同一
输入、输出和结构预算约束。

### 12.6 URI

URI adapter 对 scheme、authority、path、query 和 fragment 进行语法感知处理：

- path 由 `UriPathPolicy` 决定保留或替换；
- fragment 默认通过 `UriFragmentPolicy::Redact` 掩码；
- query 使用核心字段规则；
- 替换内容必须保持合法 percent-encoding；
- 无效 URI 失败关闭并记录 `InvalidUri`。

HTTP URL 与通用 URI 共享核心字段、掩码和预算语义，但保留各自协议策略与解析实现。

## 13. 字符与输出安全

所有最终输出必须满足：

- 始终为有效 UTF-8；
- 截断只发生在 UTF-8 边界；
- 换行、回车、tab、NUL 和其他日志控制字符经过统一 escape；
- escape 后的真实字节数计入输出预算；
- mask 与 truncation marker 本身也受预算限制；
- 输入值和未发布缓冲区不通过 `Debug` 泄露；
- `literal()` 只允许 `&'static str`，代表代码作者审核过的固定文本。

日志安全不等于协议 round-trip。格式适配器的首要目标是生成安全诊断表示，而不是重建可发送的
原始协议对象。

## 14. 错误与降级模型

错误分为三类：

### 14.1 配置错误

无效字段名、冲突规则、空固定替换、超出可分配范围的 limit 等在 policy 构建时返回
`PolicyError`。构建失败不得产生部分 policy。

### 14.2 安全降级

非法 JSON/URI、上游截断、不支持 content type、输入/输出/结构上限等返回
`RedactionTextOutput`，并通过 completion、reasons 和 usage 表达。`finish()` 不因这些状态返回
`Result`。

### 14.3 API 使用错误

batch handle 与 output 不匹配时，`resolve()` 返回 `RedactionBatchHandleError`。这是调用关系错误，
不代表脱敏算法失败。

用户代码 panic 保持 panic 语义，只负责回滚未发布状态，不包装为上述错误。

## 15. 并发、所有权与默认状态

- `RedactionPolicy` 与 `Redactor` 是不可变快照，可廉价 clone；
- composer 和 batch 拥有私有可变预算，不在线程间隐式共享；
- 每个并发工作流创建自己的 composer 或 batch；
- application default 使用 `OnceLock<RwLock<Redactor>>` 保存完整快照；
- 读取方只观察到完整旧快照或完整新快照；
- 默认替换不改变已创建对象。

本设计不提供跨线程活动 transaction，也不提供多个对象共享同一预算的 API。

## 16. 性能与存储原则

- policy 内部规则和格式策略使用 `Arc` 共享不可变数据；
- 最终发布尽量移动已有字符串，避免再次脱敏和重复记账；
- batch handle 只保存 identity 与索引，不持有文本；
- parser 在 admission 之后运行，不能先分配完整中间结构再检查预算；
- domain 与集合遍历在访问元素前检查深度、节点和 item 上限；
- mask writer、JSON writer、HTTP body writer 和 URI writer 都必须支持 bounded 写入；
- 不使用 `usize::MAX` 或局部无限预算绕过顶层限制。

性能优化不能削弱安全边界；任何缓存都必须绑定完整 policy 快照和正确的格式上下文。

## 17. 模块组织

目标源码职责如下：

```text
src/
├── facade/       Redactor、RedactedText、RedactionTextOutput、summary
├── policy/       字段规则、floor、masking、limits、policy builder
├── domain/       Redact/RedactMut traits 与借用 writer scopes
├── formats/      argv、env、process、json、http、uri adapters
├── runtime/      private runtime、budget、composer、batch、handle、buffers
└── output/       completion、日志字符 escape、内部安全输出辅助
```

公共类型应从 crate root 提供单一导出路径。实现细节保持 crate-private，不通过多个 facade 重复导出。

format 模块只公开调用方确实需要构造的输入、policy 选项和 composer writer；batch staging、预算和
最终 item 类型属于统一 runtime API。

## 18. 测试与验证策略

### 18.1 单元测试

覆盖字段匹配、floor、mask、UTF-8 截断、控制字符 escape、summary 合并、budget admission、格式
parser 与 writer 的局部不变量。

### 18.2 集成测试

覆盖：

- composer 完整链式调用和顺序；
- 异构 batch、handle 解析和 batch summary；
- 每种格式的 composer、batch 和一次性入口；
- standard、strict 与 application default；
- domain writer 和原地脱敏；
- feature gate 与 crate root 公共导出；
- panic 回滚和发布原子性；
- exact-limit、truncated、exhausted 与 malformed input。

### 18.3 编译测试

必须验证：

- 旧 API 不可导入；
- composer 与 batch 方法集互不混合；
- composer 和 batch 均由 `finish(self)` 消耗；
- handle 不可显示或转成字符串；
- 未启用 feature 时相关 API 不存在；
- derive 的无效属性、冲突模式、缺失 trait bound 和 feature 缺失产生明确错误。

### 18.4 属性测试与 fuzz

对任意输入验证：

- 输出始终为有效 UTF-8；
- 输出长度不超过预算；
- 明确 sensitive 的原文不出现在输出；
- completion 不逆向改善，usage 不倒退；
- parser 不 panic；
- handle 只能解析所属 batch；
- transaction sequence、格式嵌套和上游截断元数据保持一致。

### 18.5 文档与 CI

README、中文用户指南、crate-level docs 和所有 rustdoc 示例必须参与 doctest。默认 feature 与
`--all-features` 均需通过测试；CI 同时执行格式、lint、覆盖率和必要的 derive trybuild 测试。

## 19. 安全不变量

任何实现和扩展都不得破坏以下不变量：

1. 未经 `finish()` 不发布中间文本；
2. composer 与 batch 在公共 API 中互不混合；
3. 一次工作只有一份 policy 快照和一组资源预算；
4. format writer 和 domain writer 不创建旁路输出或旁路预算；
5. parser 在 admission 后才检查内容；
6. exhausted 后不继续访问输入；
7. floor 只能提高保护，应用 allow 不能绕过 floor；
8. 显式 sensitive 等级是最低等级，policy 只能增强；
9. `unredacted` 与未标注 derive 字段是显式信任边界；
10. 所有最终文本有效 UTF-8、控制字符安全且计入预算；
11. handle 在发布前不能转成文本，只能由所属 batch output 解析；
12. panic 不发布半成品。

## 20. 扩展规则

新增格式或公共能力时必须先回答：

1. 它产生一段组合文本、一个 batch item，还是两者都支持？
2. 输入在何处完成 admission，如何证明 parser 不会越过预算？
3. 字段上下文使用哪组 rules，安全默认值是什么？
4. 无效输入如何失败关闭，使用哪些 completion 和 reason？
5. 上游截断信息能否如实保留？
6. 控制字符、UTF-8 和协议编码如何处理？
7. composer、batch、一次性 redactor、feature gate、fuzz 和文档分别需要哪些测试？

如果一个扩展需要自己的 policy、预算、summary 或最终输出模型，应先证明它无法复用核心运行时；
默认禁止建立平行脱敏栈。
