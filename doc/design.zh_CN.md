# qubit-redact 设计文档

[English Design](design.md) · [中文用户手册](user_guide.zh_CN.md) · [README](../README.zh_CN.md)

当前 runtime：qubit-redact 0.10.0；仓库 derive：qubit-redact-derive 0.8.1。runtime 声明 derive 0.8 依赖范围；两个包的版本号独立。Rust 1.94，默认空 feature。

## 1. 目标与边界

`qubit-redact` 为日志、错误信息和技术支持诊断提供策略驱动、有资源上限的脱敏。它处理字段、
领域对象、JSON、URI、HTTP、环境变量、argv 和进程描述，并保证启用脱敏时所有已发布文本在
`Complete`、`Truncated`、`Exhausted` 三种完成状态下都不泄露未获准的原值。

本 crate 不负责内存擦除、不修改源对象，也无法保护绕过本运行时的输出。字段敏感性属于下游领域
知识：领域模型必须显式标记敏感字段，框架不会从 Rust 类型或当前内容猜测。

## 2. 核心不变量

设计由以下不变量约束：

1. `Redactor` 持有不可变的 `Arc<RedactionPolicy>` 快照；已创建的对象不受应用默认值后续替换影响。
2. 每个 composer、batch 或 inspection 拥有独立事务和独立预算账本。
3. 启用脱敏时，解析错误、输入截断和预算耗尽均 fail closed，只发布安全替代文本及原因。
4. 标量 key 先通过结构长度与输入字节准入，再做敏感判定；判定先于惰性值访问和格式化。
   标量 inspection 先准入根节点与原始 key 字节，再准入输入字节并分类。
5. 结构深度、节点数、集合项、输入字节、JSON 值和输出字节由同一事务统一计费。
6. 只有完成事务才能构造公开摘要；内部 parser 和 format executor 不发布第二套结果类型。
7. `RedactionPolicy::disabled()` 是显式调试逃生口，会恢复原值；授权和使用时机由下游负责。
8. 隐藏的结构化 Serde adapter 在直接调用时建立根准入 scope，嵌套调用则复用已有 scope；隐藏
   capability 在没有 scope 时必须 fail closed，不能绕过资源上限。

## 3. 总体架构

```text
调用方
  │
  ▼
Redactor + 不可变 RedactionPolicy 快照
  ├── RedactedTextComposer ── TextSession ──► RedactionTextOutput
  ├── redact_* ────────────── TextSession ──► RedactionTextOutput
  ├── DiagnosticRedactionBatch ──────── BatchSession ─► diagnostics + handles
  └── inspect_* ───────────── InspectionSession ─► Result<RedactionInspection, Error>
                                  │
                                  ▼
                  RuntimeCore：预算、摘要、事务阶段
                                  │
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
              domain           formats          output
       RedactionWriter       JSON/HTTP/...   转义与安全标记
```

源码按职责分为：

- `facade`：公开入口、composer、batch、输出和摘要；
- `policy`：字段规则、上下文规则、掩码与资源上限；
- `runtime`：共享事务状态、预算、结构准入、operation sink 和发布；
- `domain`：`Redact`、`RedactionWriter`、容器适配及可选 Serde 桥接；
- `formats`：argv、env、process、JSON、URI、HTTP 的解析与渲染；
- `output`：日志转义、掩码文本和完成状态。

依赖方向是 façade/domain/formats 指向 runtime 与 policy。runtime 不依赖公开 façade 的操作模型，
各 format 只返回内部 `RenderedOperation`，最终发布始终由父事务完成。

### 3.1 消费视图与两个执行账本

```mermaid
flowchart TD
    A[Redactor / Composer / Batch] --> S[scalar_operation]
    S --> R[RuntimeCore 结构与 key 准入]
    S --> C[InputCapture 原子片段准入]
    C --> O[OperationSink 转义及终结]
    O --> T[TextSession / BatchSession 发布]
    V[RedactedView] --> P[借用字段投影]
    D[派生源 Serialize] --> H[RedactSerialize]
    H --> P
    P --> B[StructuredSerdeBudget]
    B --> X[外部 Serializer]
    J[to_json] --> P
    B --> Y[to_json 使用 serde_json Serializer]
    Y --> W[BoundedJsonWriter 最终编码额度]
```

view 借用源并拥有不可变策略快照；创建不访问源，每次格式化或序列化重新执行。
文本通过 `Redact`，view 的结构化 Serde 使用隐藏的 `RedactSerializeSource` 投影能力，
可在当前序列化调用中借用字段。只有字段的普通放行模式才要求源对象实现 `Serialize`。
`#[redact(serde)]` 还会通过旧的 `RedactSerialize` 桥替换源对象的普通序列化行为。
derive 显式 level 由领域类型定义，在 strict 下保持固定。手写
`sensitive_at_least` 表示最低等级，与运行时分类取更强者，因此 strict 可以提高该下限；
未标注字段保持普通表示。

嵌套 view 投影使用 `RedactSerializeSource`，其泛型关联 view 允许 Option、Vec 等支持的
容器在当前调用中借用数据。除字段普通放行模式所需能力外，源类型不必实现普通
`Serialize`。另外，`#[redact(serde)]` 通过旧的 `RedactSerialize` 桥保留源类型普通序列化；
该路径有自己的能力边界，不等同于 view 投影。缺少 view 所需能力时在请求序列化处报错，
纯文本派生仍然有效。

受支持容器中的自递归 `nested` 字段（例如 `Option<Box<Node>>` 或
`Vec<Box<Node>>`）通过惰性子投影工厂打断递归关联类型约束。`redact_view()` 与
`to_json()` 仍遵循普通投影的字段能力要求，不会因此要求源对象一律实现普通 `Serialize`。

脱敏序列化保留源 Serde 事件形状：`Option::Some` 使用 `serialize_some`，level 模式切片使用 sequence，通过准入的固定数组使用
tuple，包装器透传目标 serializer 的 human-readable 选择。JSON 输出形状保持不变，非 JSON
serializer 则收到预期的 Option、tuple 和表示方式事件。
derive 生成的 transparent、adjacent-tagged 与 untagged 表示也遵循 Serde 生效后的事件和名称。
adjacent tag 保留枚举名、变体索引和序列化变体名。本次修正的 `Some` 与固定数组 Tuple 事件同时适用于
`#[redact(serde)]` 启用的源对象序列化和借用 view。这些修正不改变 JSON 结构，但非 JSON serializer
观察到的事件流会变化；使用旧事件写入的持久化数据可能需要旧 decoder 或显式格式版本。迁移时应由旧实现
读取旧数据，再用修正后的实现重编码；不能假设新事件布局能直接解码旧数据。其中
`Option<Map>::Some` 会发出包住 map 的 `Some` 事件。持久化数据应由旧 decoder 读取后重编码，
或使用应用级格式版本；库不会自动识别或解码旧布局。

文本 RuntimeCore 与同步 Serde scope 生命周期不同，分别拥有账本。Serde scope 使用
PolicyFrame 的 Arc 快照和线程局部 guard；嵌套及普通 serializer 复用活动预算，错误或
panic 展开会释放 scope。原始策略地址仅作为快照复用的提示，策略内容仍须与持有的
快照相等，避免 guard 被遗忘后，同一地址上的新策略误用旧快照。不能预序列化测量后
再执行第二次。

## 4. 策略模型

`RedactionPolicy` 聚合字段规则、掩码、格式策略和 `RedactionLimits`。`standard()` 提供确定性默认
策略，`strict()` 将未知字段按 `Secret` 处理，`disabled()` 明确关闭保密脱敏。

字段解析先应用基础规则，再应用 HTTP header/query/body 等上下文规则。上下文只能增强敏感度，
不能削弱已经判定为更敏感的基础结果；统一的 `ResolvedField::stronger` 实现承担该合并语义，避免
不同格式各自复制安全逻辑。

`RedactionFloor` 组合时保留相互独立的规则层，并按匹配保护中的最高敏感度解析。通过
builder 编辑组合 floor 时只修改可编辑层，其他层及其 matching/fallback 行为均保留；重新
构建后仍保持原组合语义。

`Redactor::application_default()` 从进程级槽读取快照，
`replace_application_default()` 线性化替换该槽并返回旧值。替换不会追溯改变已有 redactor、composer
或 batch。

## 5. 事务与发布模型

### 5.1 Composer

`RedactedTextComposer` 按调用顺序把 literal 和脱敏操作组合成一个结果。`literal` 只接受
`&'static str`，动态数据必须进入脱敏操作。`finish(self)` 消费 composer，并发布单个
`RedactionTextOutput`。

### 5.2 Batch

`DiagnosticRedactionBatch` 在一个共享预算内创建多个独立 item。每个操作立即返回只在该 batch 内有效的
handle；`finish_with_marker(self, marker)` 发布诊断视图：完整 item 保留安全文本，不完整、
缺失或来自其他 batch 的 handle 统一解析为已转义 marker。诊断视图同时保留 batch 聚合摘要。

### 5.3 Inspection

inspection 复用相同策略和结构预算，只记录分类、敏感度、用量和不完整原因，不发布原始值。
inspection error 表示结论不完整；安全决策应按敏感处理。

### 5.4 RuntimeCore

`RuntimeCore` 保存策略快照、`RedactionBudget`、聚合 `SummaryBuilder`、事务阶段和可选 item 摘要。
`TextSession`、`BatchSession`、`InspectionSession` 在其上实现不同发布方式。operation sink 负责把
格式结果提交给父事务，避免子格式创建独立预算或摘要。

## 6. 准入、预算、渲染和发布

一次结构化操作遵循固定流水线：

```text
输入元数据检查
  → 预算预检
  → 结构准入/解析一次
  → 策略判定
  → 有界渲染与日志转义
  → 记录 usage/reason/completion
  → 父事务发布
```

预检发生在推进不可信迭代器之前。JSON 文本在准入时解析一次并建立 admitted tree；HTTP JSON、
NDJSON 和 multipart 的渲染复用本次操作已准入的结构，生成结果时无需再次解析。渲染直接借用
已准入的 `Value` 节点，经有界 writer 输出；不会构造另一棵掩码树，也不修改已准入值。

JSON visitor 保留首个结构拒绝原因：共享结构深度拒绝映射为
`DepthLimitReached`；共享节点/集合拒绝，以及 JSON 专属预算或事务提交拒绝仍映射为
`TraversalLimitReached`。借用 `Value` 入口因此会保留与 JSON 文本 inspection 和渲染相同的共享深度原因，
不会把所有失败折叠为布尔遍历结果。

argv、环境变量列表等扁平结构格式通过同一个 runtime admission helper 计费根节点、集合项、子节点
和源字节。composer 与 batch 保留不同发布模型，但同一输入迭代器的推进和计费规则不能各自漂移。

输出不足时只保留完整 UTF-8 前缀和安全标记。`Truncated` 表示仍有安全但不完整的表示，
`Exhausted` 表示预算无法容纳完整替代。调用方应读取 `RedactionSummary`，不能通过解析标记文本
推断原因。

### 6.1 标量准入、失败事实与输出关闭

one-shot、composer、batch 共享 `runtime/scalar_operation.rs`，依次进行输出预检、根节点
准入、key 长度检查、key 输入字节准入、分类、必要时格式化。拒绝 key 只增加 presented，
不增加 inspected，不规范化或访问值；脱敏启用时，High/Secret 准入 key 后直接输出固定掩码。
标量 inspection 则先准入根节点和 key 的原始 UTF-8 字节，再计入字段和值的 input 字节；所有准入
成功后才分类。任一准入拒绝都会让 inspection 结论不完整并阻止分类，disabled 也一样。
`InputCapture` 按完整 UTF-8 片段计量，首次拒绝后永久锁存。已接受前缀仍计费，失败时全部
丢弃原文；`ScalarFailure` 区分 InputLimit 与 FormatterFailure，不携带完成状态。
显式 Low/Medium 领域文本在共享输入字节额度下只格式化源值一次；即使 formatter 失败，已接受的
UTF-8 字节仍计入输入账本。High/Secret 和 inspection 不访问源 formatter；disabled 显式文本仍受输入额度限制。

OperationSink 负责安全替代和最终状态。输入拒绝或 formatter 错误的 `<truncated>` 能完整
容纳时为 Truncated，仅保留真实原因；不能容纳时为 Exhausted，并记录实际 OutputLimitReached。
真实输出截断且标记可容纳时为 Truncated + OutputLimitReached。正常掩码为 Complete。
`RenderedOperation` 独立保存 output_closed，merge 合并该事实、原因和完成状态。
发布层不从泛化失败推断输出超限，也不丢弃前序安全文本。Exhausted 在构造边界必有输出原因。

输入失败项允许后项在剩余预算内继续，aggregate summary 仍不完整；空失败 batch item 使用不占结果
槽位的 rejected handle，整批摘要仍累计每次拒绝的原因和用量。真实输出拒绝或恰好用尽额度关闭
后续输入访问。发布后的调用方 marker 会转义，但不计入原事务输出额度。

### 6.2 Serde 载荷与最终编码

`max_input_bytes` 默认 64 KiB，`max_serde_payload_bytes`（serde feature）与
`max_output_bytes` 各默认 16 KiB；均允许 0，后两者不能超过 isize::MAX。
载荷沿 Serde 事件计量：字符串/字符 UTF-8、bytes 切片、数字/bool 标量表示，none/unit 为 0，
动态 map key 和标量形式的 unit variant 名称计入，静态字段名、标点、转义及 framing 不计入。

旧式 `RedactSerialize` hook 在根调用时使用显式传入的策略，嵌套调用则加入活动 scope。裸的
`RedactSerializeSource` 投影只借用字段、不保存策略；缺少活动 scope 时序列化会返回不含原值的
serializer 错误。普通调用方应使用 `redact_view()` 或 `to_json()`。直接序列化 view/source
使用结构、输入和逻辑载荷额度；最终编码由调用方 serializer/writer 控制。`to_json` 使用相同字段投影并通过独立 BoundedJsonWriter 限制全部最终编码字节，
包括标签、转义、引号、标点和掩码。它一次遍历，只有完整编码成功才返回 String；原有
Result<String, serde_json::Error> 保留。结构降级可以产生合法安全替代，故成功不代表完整。
同一源状态且两者均成功时，to_json 与直接序列化 view 输出一致；成功条件不等价。

文本字段、手写领域节点及 Serde 事件各有输入准入单位；usage 不是源对象内存大小。
预算无法抢占用户 Display/Serialize 内部任意计算，也不限制调用前分配。

## 7. 领域对象与 Serde

`Redact::write_redacted` 只能通过 `RedactionWriter` 写入当前事务。writer 支持 record、sequence、
map、嵌套对象、按敏感等级写入、按运行时 key 分类、JSON 值和显式 skip。所有 scope 共享父事务
预算，深度或集合上限失败时关闭对应结构，不创建旁路输出。

`derive` feature 导出 `#[derive(Redact)]` 和 `#[derive(RedactScalar)]`；生成的序列化适配还需要 `serde` feature。隐藏的支撑
trait 与借用 adapter 覆盖标量、可选值、引用、常用容器、tuple、map 和 JSON ownership 形态。
这些符号保持公开只是因为生成代码会在下游 crate 中展开，并不是另一套面向用户的序列化 API。
根 adapter 建立或复用 thread-local 结构预算。借用字段投影通过 `RedactSerializeSource` 支持
Option、Vec、固定数组和 tuple 等已有容器；切片不支持 nested 投影。切片能力属于显式 level
脱敏，level 模式切片序列化为 sequence，通过准入的固定数组序列化为 tuple。投影要求已有
scope；缺少 scope 时，即使容器为空，也返回不含原值的 serializer 错误。因此直接构造
不能跳过集合、深度、节点和输入准入。internally tagged serializer 只接受能够保持目标结构的 map/struct 形态，不支持的
Serde shape 返回明确错误而不是猜测表示。

## 8. 格式层

- argv/env/process：显式分类和受限启发式；未分类的非 UTF-8 参数项及非 UTF-8 环境变量名保守分类为 Secret；
- JSON：一次解析、递归字段分类、显式数字范围和共享结构预算；
- URI：使用 `fluent-uri` 解析，并分别处理 identity、path、query、fragment；
- HTTP：处理 URL、header 和 body，所有结果回到父事务。URL query 参数使用 query 规则；
  `application/x-www-form-urlencoded` body 中的 form 字段使用 body 规则。

HTTP body 内部实现按职责拆分：

- `src/formats/http/internal/http_policy_executor/body.rs`：准入结果分派和最终 publication；
- `json_body.rs`：JSON 与 NDJSON；
- `form_body.rs`：`application/x-www-form-urlencoded`；
- `multipart_body.rs`：multipart part、嵌套 content type 和文件内容；
- `text_body.rs`：text、binary 和 unsupported fallback；
- `url.rs`：URL、nested URL 和 query；
- `headers.rs`：header；
- `diagnostics.rs`：有界诊断文本与完成状态。

native `HeaderValue` 与文本 Content-Type inspection 都先原子准入 body capture 和 metadata 字节，
之后才解码或检查 metadata。输入被拒绝时只记录真实准入原因，不报告 `InvalidContentType`；
准入成功但 native header 非法时，先计费再记录该原因。

这些模块共享私有 `HttpPolicyExecutor`，它只借用父 session 的 policy，不拥有 session，也不产生
公开 HTTP result。无效 content type、缺失 multipart boundary、非法 JSON/NDJSON 和截断输入均
通过安全 marker 与结构化 reason 表达。

Multipart 内嵌 JSON/NDJSON 的解析失败保留 `InvalidJson`，资源准入失败保留对应 limit reason。
嵌套 URL 渲染则把子操作的 `InvalidUri` 和 `DepthLimitReached` 原因合并到父结果。
Multipart framing 会先由借用的 segment 游标完整校验，再逐段消费。辅助 segment 状态不随原始
segment 数量增长；admitted slot 只为通过准入的 part 增长。顶层 form 字段使用深度 2，multipart
part 内的 form 字段在 inspection 与渲染中都使用深度 3。已准入的 JSON 与 NDJSON 结构只解析一次并复用。
NDJSON 只保存非空值及其源行索引，空行单独计数，使连续空行的辅助空间保持常量；渲染通过有界 writer
恢复换行，multipart NDJSON 也保留源行位置。

### 8.4 URL 解析基准结论

基准输入在计时外构造，分别测量 one-shot 和单项 batch。Criterion 每项使用 30 个样本、1 秒预热、
2 秒测量；环境为 Linux x86_64、Rust/Cargo 1.94.0。每轮命令为
`cargo bench --bench http_uri_bench --features http,uri -- --save-baseline rr04-before-N --sample-size 30 --warm-up-time 1 --measurement-time 2`。
下表各数值为均值点估计及 95% 置信区间，单位微秒，按第 1/2/3 轮排列。

| 场景 | One-shot 第 1 / 2 / 3 轮 | 单项 batch 第 1 / 2 / 3 轮 |
| --- | --- | --- |
| 短 URL | 28.92 [23.37, 34.82] / 43.63 [31.46, 57.88] / 39.09 [31.75, 47.10] | 26.75 [22.86, 31.06] / 29.85 [23.45, 36.37] / 53.58 [42.27, 65.48] |
| 128 项 query | 484.35 [374.84, 623.90] / 1040.61 [926.06, 1169.31] / 3605.74 [2812.33, 4453.14] | 1803.58 [1648.05, 1957.43] / 701.74 [535.35, 885.03] / 2967.35 [1593.08, 4852.11] |
| 三层嵌套 URL | 104.33 [88.78, 120.71] / 75.57 [58.85, 93.35] / 208.09 [165.37, 254.83] | 142.44 [115.09, 172.99] / 89.06 [63.23, 126.42] / 170.58 [123.05, 223.77] |

轮次间波动远大于预设的 5% 收益门槛，区间无法支撑稳定的优化前基线，因此没有测量或保留根 URL
复用候选。RR-04 以“核查完成，不做生产优化”闭环；基准保留，供后续受控对比使用。

来源截断元数据只由 `BodyCapture` 持有。当已捕获 body 超过父 runtime 的剩余输入额度时，父事务
会原子拒绝整段 body；renderer 不再维护第二套“部分输入”状态。native 与文本 inspection 的
Content-Type 字节也与 body 一起原子准入。已解析的来源截断 body 会保留
`SourceTruncated`；若输出也无法容纳，则同时报告 `OutputLimitReached`。URL 和 form
渲染发生输出截断时报告 `OutputLimitReached`，不会标为 `Complete`。

## 9. Feature 与兼容性

默认 feature 为空：

- `derive`：派生宏；
- `serde`：领域序列化适配；
- `bigdecimal`：BigDecimal 标量和等级能力，同时启用 `serde`；
- `json`：Serde JSON 与 `qubit-json`；
- `http`：包含 `json`，并增加 HTTP、URL、form/multipart 支持；
- `uri`：`fluent-uri` URI 支持。

公开入口位于 `Redactor`、composer、batch、inspection、policy 和 domain writer。format executor、
admitted tree、runtime session 和 sink 保持 crate-private。

0.8 的公开批处理入口为 `diagnostic_batch()`；`finish()` 使用默认诊断标记，
`finish_with_marker(marker)` 使用自定义标记。BigDecimal 能力通过独立的 `bigdecimal`
feature 启用，不再随仅需结构化序列化的 `serde` 消费者一同引入。直接 Serde 沿用 0.6 之后
引入的独立 `max_serde_payload_bytes` 预算；`max_output_bytes` 限制最终文本和 `to_json()`
编码。文本失败标记与原因按真实准入及输出拒绝生成。

derive crate 通过仅含 path 的开发依赖引用 workspace runtime，以执行 rustdoc 示例。
Cargo 从发布清单移除这条本地依赖，保持先 derive、后 runtime 的发布顺序，不产生 registry
依赖环。`cargo publish --workspace --dry-run --all-features` 验证两个规范化发布包，但不会上传。

## 10. 验证策略

`.infra/bin/ci-check.sh` 读取 `.infra/ci/cargo-matrix.json` 执行兼容性检查。除 core 和各格式 feature 外，
矩阵覆盖 derive-only、derive 与 Serde/JSON/HTTP/URI 的组合、BigDecimal 单独启用及与
derive 组合，以及全部 feature；展开隐式依赖后覆盖全部 28 种 runtime feature 集。每组执行编译、测试（含 doctest）、rustdoc 和 Clippy；
文档示例按真实依赖设置 feature gate。
项目 CI hook 还会依次运行接线测试、校验脚本测试和两种语言文档中的带注解示例。

下游负向编译测试读取 Cargo JSON compiler message。只有在 fixture 源码具有 primary span、
且匹配预期 API 或 trait 的 rustc error 才算预期拒绝；指定错误码时还必须精确匹配。
Cargo 依赖解析失败和工具链失败均不能作为 API 拒绝证据。正向消费 fixture 同时验证
受支持 API 在相同环境下能够编译。

runtime 覆盖率门禁不使用文件白名单。单元与集成测试覆盖公开策略 builder、限制、领域 writer、sealed
capability、Serde shape、所有格式的正常与 fail-closed 路径，以及 composer/batch/inspection
发布约束。覆盖率要求为函数至少 95%、行和 region 均严格大于 90%。

fuzz target 分别覆盖直接 URI/URL、命令输入、混合事务序列、JSON 文本、HTTP body、multipart
body、隐藏的结构化 Serde map adapter，以及 derive/view/to_json 消费入口。
混合事务使用小预算边界并断言 inspected/output 上限及 Exhausted 原因；有效 NDJSON 还验证公开字段和无 InvalidJson。固定敏感值断言验证“不泄露”，任意字节路径验证确定性、
UTF-8 输出、直接 adapter 的有界行为和无 panic。Criterion workload 除标量、领域对象和 JSON 外，
还覆盖下游重度使用的 argv、环境变量、进程、HTTP 和 URI。CI 还执行格式、style、Clippy、测试、
rustdoc 与 doctest。消费 benchmark 分别测 view 创建、重复 Display/Serde、redact_text、to_json、
集合规模和输入/载荷/最终编码边界，构造置于计时外，不把耗时当作正确性门槛。

## 11. 有意不做的事情

- 不自动推断领域字段敏感性；
- 不提供绕开事务的公开 formatter 或可伪造摘要；
- 不承诺原值内存清零；
- 不把 `disabled()` 包装成授权系统；
- 不为 HTTP 或 JSON 建立独立于事务的公开输出模型；
- 不在预算耗尽后继续遍历不可信输入以追求更完整的诊断。
