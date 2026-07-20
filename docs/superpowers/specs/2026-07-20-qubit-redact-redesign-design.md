# qubit-redact 破坏性重构与领域对象脱敏设计

- 日期：2026-07-20
- 状态：已批准，可进入实施
- 主仓库：`/home/starfish/working/qubit/rust-common/rs-sanitize`
- 同步迁移仓库：`rs-http`、`rs-command`、`rs-config`
- 参考设计：
  `/tmp/superpowers-rs-sanitize-design-LpsJMa/2026-07-20-rs-sanitize-domain-object-design.md`

## 1. 决策摘要

本次重构不保留源代码、Cargo feature 或旧包名兼容性。最终发布物使用：

- Cargo package：`qubit-redact`
- Rust crate：`qubit_redact`
- proc-macro package：`qubit-redact-derive`
- proc-macro crate：`qubit_redact_derive`
- 初始版本：`0.1.0`
- Rust edition：2024
- MSRV：1.94

主 crate 暂时保留在当前 `rs-sanitize` 本地目录中；GitHub 仓库和本地目录由仓库所有者
后续改名。在 GitHub 真正改名前，Cargo metadata 继续指向当前有效仓库地址。

公共模型收敛为：

1. `RedactionPolicyBuilder`：唯一可变配置入口。
2. `RedactionPolicy`：不可变字段规则、名称匹配与遮盖策略，并支持一次性安装进程级默认。
3. `Redactor`：执行字段值及 Map 脱敏。
4. `RedactedText` / `LogSafeText`：区分已脱敏文本与日志安全文本。
5. `argv::ArgvRedactor` / `env::EnvRedactor`：零外部依赖 adapter。
6. 可选 `http` feature 下的 `http::HttpRedactor`。
7. `Redact`、`RedactMut`、`Redacted<'_, T>`：领域对象脱敏。
8. 可选 `derive` feature 下的两个 derive 宏。

## 2. 背景

现有实现的匹配、遮盖和 fail-closed 行为整体可靠，但公共 API 存在以下结构问题：

1. `NameMatchMode` 由每个调用点重复传入，而三个生产下游均固定使用后缀匹配。
2. `SensitiveFields`、`FieldSanitizePolicy`、`FieldSanitizer` 和各 adapter 重复暴露
   可变配置方法。
3. 排除规则在后缀匹配下可能产生超出名称直觉的宽泛放行。
4. HTTP Body API 不自行强制输入预算，完整 JSON 路径会构造 DOM 并重新序列化。
5. 已脱敏文本和完成日志转义的文本均表示为普通 `String` / `Cow<str>`。
6. `sanitize` 容易被误解为完整输入净化或任意秘密检测，实际能力是按明确规则
   redaction。
7. 动态字段 API 无法直接表达领域对象字段规则。

## 3. 目标

1. 统一使用 `redact` 术语。
2. 所有字段匹配配置只存在于不可变 `RedactionPolicy`。
3. 默认包含现有全部预定义敏感字段，默认使用 token-boundary 后缀匹配。
4. `RedactionPolicy` 实现 `Default`，并允许在启动阶段一次性安装全局默认策略。
5. 完整保留单值、Map 副本、Map 原地修改、预置字段、自定义字段和自定义遮盖。
6. 精确放行与后缀放行使用不同 API，并采用确定的最长匹配优先级。
7. 在类型层面区分已脱敏文本和可直接写入文本日志的内容。
8. HTTP 能力保留在主 crate，通过非默认 `http` feature 提供。
9. HTTP Body 只提供有界日志/诊断预览，强制输入与输出预算。
10. derive 支持领域对象非破坏式视图、显式 Map redaction、可选 serde 和显式破坏式脱敏。
11. 四个仓库一次性迁移，不保留 deprecated alias 或 feature alias。
12. 关闭全部 feature 时，主 crate 保持零外部依赖。

## 4. 非目标

1. 不根据值内容猜测秘密，不实现 DLP、熵检测或正则扫描器。
2. 不重写完整 HTTP 请求体，不处理代理流、解压缩或业务 payload 转换。
3. 不默认修改领域对象原有的 `Debug`、`Display`、`Serialize` 或字段值。
4. 不提供脱敏对象反序列化。
5. 第一版 derive 不支持 enum、union、tuple struct、unnamed field 或
   `serde(flatten)`。
6. 领域对象字段必须显式使用 `#[redact(level = "secret")]`、`nested`、`map` 或 `skip`，
   不根据 Rust 字段名推断。
7. 未标注的 Map 不隐式应用字段规则；只有 `#[redact(map)]` 才按 key redact value。
8. 本次不执行 GitHub 仓库改名。
9. 不保留旧包名、crate 名、类型或 feature 兼容层。

## 5. 包与 feature

### 5.1 同仓库 companion crate

```text
rs-sanitize/                       # 后续改名 rs-redact
├── Cargo.toml                     # qubit-redact + workspace root
├── src/
├── tests/
├── fuzz/
└── derive/
    ├── Cargo.toml                 # qubit-redact-derive
    ├── src/
    └── tests/
```

主 crate 以 optional dependency 依赖 derive crate；derive crate 不依赖主 crate。宏通过
`proc-macro-crate` 解析调用方实际使用的 crate 名，支持 dependency rename。

### 5.2 feature

```toml
[features]
default = []
derive = ["dep:qubit-redact-derive"]
serde = ["dep:serde"]
http = [
    "dep:form_urlencoded",
    "dep:http",
    "dep:serde_json",
    "dep:url",
]
```

- core、argv、env 及领域对象 runtime traits 永远可用且零外部依赖。
- `derive` 重导出 `Redact` / `RedactMut` derive 宏。
- `serde` 启用 `Redacted<'_, T>` 的可选序列化 runtime。
- `http` 一次性启用 URL、form、Header 和 Body。
- 删除旧 `form`、`web` 及默认 HTTP feature 组合。
- HTTP 内部使用 `serde_json`，不隐式启用公开 `serde` feature。

## 6. 公共模块

```text
qubit_redact
├── RedactionPolicy / RedactionPolicyBuilder / PolicyError
├── GlobalDefaultAlreadySet
├── Redactor / RedactedText / LogSafeText
├── Sensitivity / MaskPolicy / MaskingPolicy
├── FieldNameMatching / SensitiveFieldPreset
├── Redact / RedactMut / Redacted / RedactedValue / RedactedMap
├── RedactValue / RedactValueMut / RedactMapValue / RedactMapValueMut
├── redacted_debug
├── argv::{ArgvItem, ArgvRedactor, RedactedArgv}
├── env::{EnvRedactor, RedactedEnvPair}
└── http::{
      HttpRedactionPolicy, HttpRedactionPolicyBuilder, HttpRedactor,
      BodyBudget, BodyCapture, BodyRedaction, BodyRedactionStatus,
      BodyRedactionReason, RedactedHeaders
    }
```

核心类型从 crate root 重导出；格式 adapter 使用命名模块。JSON、multipart、
content-type、header parameter 和 fallback parser 均保持私有。

## 7. 字段策略模型

### 7.1 基础类型

```rust
#[non_exhaustive]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Secret,
}

#[non_exhaustive]
pub enum FieldNameMatching {
    Exact,
    ExactOrTokenSuffix,
}
```

`Sensitivity` 保留现有等级顺序。`ExactOrTokenSuffix` 保留当前规范化、分隔符及
camel-case boundary 行为。

`MaskPolicy` 表示单个等级算法；`MaskingPolicy` 替代 `MaskPolicies`，保存四级不可变
配置。默认语义保持：

- Low：保留前后各两个 Unicode scalar；
- Medium：仅保留最后一个 Unicode scalar；
- High：`****`；
- Secret：`<redacted>`；
- 空字符串保持为空。

`MaskingPolicy` 使用共享不可变数据，clone 为常量成本。

### 7.2 Default 与进程级默认

`RedactionPolicy` 实现 `Default`。进程级默认使用一次性安装而不是可替换的全局可变
配置：

```rust
impl RedactionPolicy {
    pub fn standard() -> Self;

    pub fn global_default() -> Arc<Self>;

    pub fn set_global_default(
        policy: Self,
    ) -> Result<(), GlobalDefaultAlreadySet>;
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::global_default().as_ref().clone()
    }
}
```

语义固定为：

1. `standard()` 始终返回编译进 crate 的内置安全策略，不受进程状态影响。
2. 尚未安装全局策略时，`global_default()` 返回 standard policy。
3. `set_global_default()` 在进程生命周期内只能成功一次；重复调用返回
   `GlobalDefaultAlreadySet`，不会替换现有策略。
4. 安装应在进程启动、创建 redactor 或生成 redacted view 之前完成。
5. `RedactionPolicy::default()`、各 adapter 的 `Default` 和 `Redact::redacted()` 都在
   调用时取得全局默认快照。
6. 已创建的 policy、redactor 和 view 不随之后的全局安装发生变化。
7. 不提供 reset API；测试应优先显式传 policy，全局安装行为使用独立测试进程验证。

### 7.3 builder

```rust
let policy = RedactionPolicy::builder()
    .matching(FieldNameMatching::ExactOrTokenSuffix)
    .include_preset(SensitiveFieldPreset::Session)
    .raise("tenant_token", Sensitivity::High)
    .override_level("license_key", Sensitivity::Secret)
    .allow_exact("public_token")
    .allow_suffix("diagnostic_token")
    .mask(Sensitivity::Secret, MaskPolicy::fixed("[hidden]"))
    .build()?;
```

1. `builder()` 从当前 `RedactionPolicy::default()` 快照开始。
2. `empty_builder()` 是唯一从空字段集开始的入口，文档明确标为弱化保护。
3. `builder_from(&base)` 从不可变策略复制配置，供不同上下文分化。
4. 需要忽略已安装全局策略并从内置规则开始时，调用
   `builder_from(&RedactionPolicy::standard())`。
5. `raise` 只提高等级；`override_level` 无条件替换精确规则。
6. `allow_exact` 只允许完整规范化字段名。
7. `allow_suffix` 明确允许 contextual token suffix，文档标为宽泛放行。
8. builder 操作按调用顺序应用。
9. `build()` 统一验证空字段名、空 replacement 及非法配置并返回 `PolicyError`。
10. `RedactionPolicy` 不提供任何可变方法。

### 7.4 匹配优先级

字段名沿用现有 canonicalization：Unicode lowercase，并删除 `_`、`-`、`.`、`[`、`]`
和空白；原始 token boundary 用于生成 suffix 候选。

候选从最长到最短处理：

1. 完整输入候选可匹配 `allow_exact`；
2. token suffix 候选可匹配 `allow_suffix`；
3. 同一候选的显式 allow 优先于敏感等级；
4. 若候选存在敏感等级，立即返回该等级；
5. 只有当前候选无任何规则时才检查更短候选。

因此 `allow_exact("access_token")` 不放行 `OPENAI_ACCESS_TOKEN`；
`allow_suffix("access_token")` 才会宽泛放行，且更短的 `token` 规则不会推翻较长候选。

### 7.5 预定义字段与查询

完整保留现有 `Credentials`、`CredentialContainers`、`AuthTokens`、`Http`、`Session`
及 extra fields。`RedactionPolicy::standard()` 包含全部规则；未安装全局策略时，
`RedactionPolicy::default()` 与 `builder()` 以它为基础。

```rust
pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity>;
pub fn matching(&self) -> FieldNameMatching;
pub fn masking(&self) -> &MaskingPolicy;
pub fn sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>>;
pub fn allow_rules(&self) -> impl Iterator<Item = AllowRule<'_>>;
```

`SensitiveFieldPreset::fields()` 继续支持只读检查；不再公开可变 `SensitiveFields`。

## 8. Redactor、Map 与文本类型

### 8.1 单字段与 Map

```rust
let redactor = Redactor::new(policy);
let value = redactor.redact("OPENAI_API_KEY", "sk-123");
```

```rust
pub fn redact<'a>(
    &self,
    field: &str,
    value: &'a str,
) -> RedactedText<'a>;

pub fn redact_map<M>(&self, map: &M) -> M
where
    for<'a> &'a M: IntoIterator<Item = (&'a String, &'a String)>,
    M: FromIterator<(String, String)>;

pub fn redact_map_in_place<M>(&self, map: &mut M)
where
    for<'a> &'a mut M:
        IntoIterator<Item = (&'a String, &'a mut String)>;
```

匹配模式来自 policy。`Redactor` 共享不可变 policy，clone 为常量成本。
`Redactor::default()` 在创建时取得 `RedactionPolicy::global_default()` 的快照；
`Redactor::new(policy)` 始终使用显式策略。

Map API 继续支持 `HashMap<String, String>`、`BTreeMap<String, String>` 及符合相同约束
的自定义容器。副本 API 保留键并返回同一 Map 类型；原地 API 只替换命中规则的值。
Map 的字符串值表示已脱敏数据，不代表已经完成日志字符转义。

### 8.2 RedactedText

`RedactedText<'a>` 包装 `Cow<'a, str>`：

- 未命中字段时借用原值；
- 命中时持有遮盖后的 owned value；
- 提供 `as_str()`、`into_owned()`、`escape_for_log()`；
- 实现安全的 `Debug`；
- 不实现 `Display`，避免未命中值中的控制字符直接进入文本日志。

### 8.3 LogSafeText

`RedactedText::escape_for_log()` 返回 `LogSafeText`，并转义：

- ASCII/C0/C1 控制字符；
- Unicode line/paragraph separator；
- 双向格式控制字符。

`LogSafeText` 实现 `AsRef<str>`、`Debug`、`Display`。其公开构造器只接受已验证或已转义
内容，普通 `String` 不能无检查转换为 `LogSafeText`。

## 9. argv 与 env

### 9.1 argv

主入口要求调用方显式传递其掌握的敏感度：

```rust
pub struct ArgvItem<'a> {
    value: &'a OsStr,
    sensitivity: Option<Sensitivity>,
}

pub fn redact_items<'a, I>(&self, items: I) -> RedactedArgv
where
    I: IntoIterator<Item = ArgvItem<'a>>;
```

提供 `ArgvItem::plain(value)` 与 `ArgvItem::sensitive(value, level)`。
`RedactedArgv::Display` 输出日志安全的一行诊断文本。

保留 `--token=value`、`--token value`、`NAME=value` 和 `--` 启发式，但入口明确命名为：

```rust
pub fn redact_heuristically<'a, I>(&self, items: I) -> RedactedArgv
where
    I: IntoIterator<Item = ArgvItem<'a>>;
```

该入口先服从每个 `ArgvItem` 的显式 sensitivity，再只对 plain item 执行启发式；只有 raw
argv 的调用方可把每项映射为 `ArgvItem::plain`。非 UTF-8 敏感值继续 fail-closed。
adapter 不再暴露 `inner_mut` 或字段规则修改方法。

### 9.2 env

`EnvRedactor` 根据环境变量名使用底层 policy：

```rust
pub fn redact_pair(&self, name: &str, value: &str) -> RedactedEnvPair;
pub fn redact_os_pair(&self, name: &OsStr, value: &OsStr) -> RedactedEnvPair;
pub fn redact_assignment(&self, assignment: &str) -> RedactedEnvPair;
```

`RedactedEnvPair::Display` 保证日志安全。非 UTF-8 key 或 value 对 value 使用 Secret 级别
fail-closed。字段配置只能在创建 adapter 前通过 policy builder 完成。

## 10. HTTP feature

### 10.1 高层模型

HTTP 只公开一个执行门面：

```rust
pub struct HttpRedactor {
    policy: HttpRedactionPolicy,
}
```

`HttpRedactionPolicy` 持有：

- header `RedactionPolicy`；
- query/form `RedactionPolicy`；
- body `RedactionPolicy`；
- URL path policy；
- 未知文本 body policy；
- unkeyed JSON value policy；
- `BodyBudget`。

默认从同一个 `RedactionPolicy::default()` 克隆三个上下文策略，调用方可从 base 创建差异：

```rust
let base = RedactionPolicy::default();
let headers = RedactionPolicy::builder_from(&base)
    .allow_exact("x-public-token")
    .build()?;

let http_policy = HttpRedactionPolicy::builder(base)
    .header_policy(headers)
    .body_budget(BodyBudget::new(16 * 1024, 64 * 1024)?)
    .build();
```

构建完成后全部 policy 不可变。若调用方未覆盖预算，builder 使用 16 KiB 输入、64 KiB
输出的安全默认值；不存在缺少预算或无限预算状态。

### 10.2 URL、form 与 Header

```rust
pub fn redact_url(&self, url: &Url) -> LogSafeText<'static>;
pub fn redact_url_str(&self, input: &str) -> LogSafeText<'static>;
pub fn redact_form(&self, input: &str) -> LogSafeText<'static>;
pub fn redact_headers(&self, headers: &HeaderMap) -> RedactedHeaders;
```

保持并收紧现有规则：

- URL userinfo、password、fragment 和默认 path policy 继续隐藏；
- query/form 按对应字段 policy 处理；
- 无法解析的 URL、query 或 form 返回固定 marker，不把错误交给调用方后回退原文；
- `HeaderValue::is_sensitive()` 始终使用 Secret，且不受 allow rule 影响；
- 非 UTF-8 Header 使用固定 marker；
- `RedactedHeaders` 的 `Debug` / `Display` 不包含原始敏感值并完成控制字符转义。

### 10.3 BodyCapture

删除 `BodySourceLength` 及其静默修正，改用受检构造器：

```rust
pub struct BodyCapture<'a> { /* private fields */ }

impl<'a> BodyCapture<'a> {
    pub fn complete(bytes: &'a [u8]) -> Self;

    pub fn truncated(
        bytes: &'a [u8],
        total_len: Option<usize>,
    ) -> Result<Self, BodyCaptureError>;
}
```

当 `total_len` 存在时必须严格大于 `bytes.len()`，否则返回
`BodyCaptureError::InvalidTotalLength`。`complete` 的 source length 恒等于
`bytes.len()`，不再存在矛盾 metadata。

### 10.4 BodyBudget

```rust
pub struct BodyBudget {
    max_input_bytes: usize,
    max_output_bytes: usize,
}
```

`max_input_bytes` 必须大于零；`max_output_bytes` 必须至少容纳固定 truncation marker，
由 `BodyBudget::new` 验证。输出上限包含 marker，而不是只限制 marker 前的 payload。
`HttpRedactor` 始终执行：

1. 最多查看 `max_input_bytes`；
2. 超出部分只取前缀并标记 effective truncation；
3. structured parser 只能访问该有界前缀；
4. 日志转义后再次限制 `max_output_bytes`，需要 marker 时先为完整 marker 预留空间；
5. 所有截断都反映在 metadata 和 suffix；
6. 不提供无限预算哨兵。

### 10.5 Body API

```rust
pub fn redact_body(
    &self,
    capture: BodyCapture<'_>,
    content_type: Option<&HeaderValue>,
) -> BodyRedaction;
```

删除无界完整 Body 转换、`raw_content`、`into_raw_content` 以及由调用方自行保证大小的
preview 入口。

保留 JSON、NDJSON、form、multipart、UTF-8 text fallback 和 binary summary。默认继续
fail-closed：

- 无键 JSON scalar 默认隐藏；
- 不透明文本默认隐藏；
- multipart file part 默认隐藏；
- 敏感命名字段按 body policy 遮盖；
- malformed structured input 返回固定 marker；
- binary 只输出长度摘要。

### 10.6 BodyRedaction

```rust
pub struct BodyRedaction {
    text: LogSafeText<'static>,
    status: BodyRedactionStatus,
    captured_len: usize,
    source_len: Option<usize>,
    omitted_len: Option<usize>,
    truncated: bool,
}
```

`BodyRedaction` 只暴露 `log_safe_text()` 和 consuming counterpart，并实现 `Display`；
不暴露未转义内容。它保留 `Empty`、`Redacted(reason)`、`Structured`、
`PassedThrough`、`Binary` 等状态。源 capture、输入预算和输出预算导致的截断统一反映在
metadata 与 suffix 中。

## 11. 领域对象脱敏

### 11.1 runtime 与 derive

```text
qubit-redact
├── Redact / RedactMut runtime trait
├── Redacted<'a, T>
├── RedactValue / RedactValueMut
├── RedactedValue<'a>
└── 可选 serde runtime

qubit-redact-derive
├── #[derive(Redact)]
└── #[derive(RedactMut)]
```

derive crate 只生成代码，不依赖 runtime；主 crate 启用 `derive` 时重导出两个宏。

### 11.2 属性

```rust
#[derive(Redact)]
#[redact(serde)]
struct Account {
    id: u64,

    #[redact(level = "medium")]
    mobile: Option<String>,

    #[redact(level = "secret")]
    password: String,

    #[redact(nested)]
    profile: Profile,

    #[redact(map)]
    metadata: HashMap<String, String>,

    #[redact(skip)]
    internal_cache: CacheHandle,

    nickname: String,
}
```

字段模式互斥：

- 无属性：原样进入 redacted view；
- `level = "low|medium|high|secret"`：按明确等级遮盖，不执行字段名推断；
- `nested`：递归调用字段类型的 `Redact`；
- `map`：把 Map key 视为动态字段名，按当前 view 的 `RedactionPolicy` redact value；
- `skip`：字段名和值均不进入 redacted `Debug`、`Display` 和 serde 表示。

即使未标注字段的类型实现了 `Redact`，也不会自动递归；递归必须显式使用 `nested`。
`skip` 只影响 redacted 表示，不改变原对象的 `Debug`、`Display` 或 `Serialize`，并免除
该字段在 redacted 路径中的格式化和序列化 trait bound。

struct 上的 `#[redact(serde)]` 显式生成 serde hook。Cargo feature 合并不会迫使未声明该
属性的类型满足 serde 约束。

### 11.3 非破坏式视图

```rust
pub trait Redact {
    fn redacted(&self) -> Redacted<'_, Self>
    where
        Self: Sized;

    fn redacted_with(
        &self,
        policy: &RedactionPolicy,
    ) -> Redacted<'_, Self>
    where
        Self: Sized;

    #[doc(hidden)]
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result;
}
```

`Redacted<'a, T>` 借用原对象并持有 cheap-clone 的完整 `RedactionPolicy`。创建 wrapper
不读取或分配字段值，真正格式化或序列化时才逐字段处理。

```rust
format!("{:?}", account.redacted());
format!("{}", account.redacted());

let strict = account.redacted_with(&strict_policy);
let json = serde_json::to_string(&strict)?;
```

- `redacted()` 在创建 view 时快照全局默认 policy；
- `redacted_with(&policy)` 使用调用方指定的 policy；
- `level` 字段使用 `policy.masking()`；
- `map` 字段使用完整 policy；
- `nested` 把同一个 policy 继续传给子对象，不在递归途中重新读取全局默认；
- `Debug` 使用标准 struct 风格并支持 pretty formatting；
- `Display` 先使用 redacted Debug hook 生成只包含已遮盖敏感字段的中间文本，再对整段文本
  执行日志控制字符转义；该实现允许一次受控分配，以保证自定义非敏感字段的 Debug 输出也
  不注入日志控制字符；
- `Serialize` 只在启用 `serde` 且 struct 声明 `#[redact(serde)]` 时存在；
- 原始对象的 `Debug`、`Display`、`Serialize` 完全不受影响；
- `Redacted` 不实现 `Deserialize`。

### 11.4 值级 trait

标注为 `level` 的字段不调用其原始 `Debug`、`Display` 或 `Serialize`，只调用：

```rust
pub trait RedactValue {
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a>;
}
```

runtime 第一版支持：

- `String`；
- `str` 与 `&str`，仅用于非破坏式视图；
- `Cow<'_, str>`；
- 上述类型的 `Option<T>`。

`RedactedValue` 保留文本与 Option 容器语义，实现 `Debug`；其 `Display` 必须完成日志
控制字符转义；启用 feature 时实现 serde `Serialize`。应用自己的文本 newtype 可显式
实现 `RedactValue`；derive 不会把任意 `Debug` 输出隐式转换成文本。

`nested` 支持直接对象以及 `Option<T>`、`Box<T>`、`Vec<T>` 的递归 blanket
implementation。未标注 Map 不执行字段名推断。

### 11.5 Map 字段

`#[redact(map)]` 使用专用 runtime wrapper，而不是复用 `nested`：

```rust
pub trait RedactMapValue {
    fn fmt_redacted_map(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result;
}

pub trait RedactMapValueMut {
    fn redact_map_in_place(&mut self, policy: &RedactionPolicy);
}
```

runtime 为符合动态 Map 约束的 `HashMap<String, String>`、`BTreeMap<String, String>`
及同类容器提供实现。非破坏式路径创建借用的 `RedactedMap<'_, M>`，在
`Debug` / `Display` / serde 遍历时逐项调用 `Redactor::redact(key, value)`，不预先复制
整个 Map。`RedactMut` 路径调用等价于 `redact_map_in_place()` 的操作。

所有 `map` 字段使用 view 持有的同一 policy：

```rust
account.redacted();              // 全局默认 policy 的快照
account.redacted_with(&policy);  // 显式指定 policy
```

第一版不支持字段级 `policy = "custom_policy"`。需要不同策略时，调用方应把该 Map 包装成实现
`Redact` 的领域 newtype，并在外层使用 `nested`。

### 11.6 serde

启用 `serde` 且声明 `#[redact(serde)]` 后，derive 实现隐藏 hook：

```rust
#[doc(hidden)]
pub trait RedactSerialize {
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}
```

生成代码只引用 `qubit_redact` 重导出的隐藏 serde 路径，使用方不需要为宏展开额外声明
直接 serde 依赖。声明 `#[redact(serde)]` 但未启用 feature 时，runtime 提供的隐藏
feature-guard macro 只生成一条定向 `compile_error!`，避免同时产生大量缺失 serde
路径的次生错误。

规则：

- 未标注字段使用正常 `Serialize`；
- 文本敏感字段输出遮盖后的 serializer string；
- `Option::None` 保持 null/缺失语义，`Some` 保持 option container；
- `nested` 递归 redacted serialization；
- `map` 保持 Map key 和容器形状，只替换命中 policy 的 value；
- `skip` 不进入结果；
- serializer error 直接传播，禁止回退原始值。

第一版识别 struct 的 `serde(rename_all)`，以及 field 的 `serde(rename)`、`skip`、
`skip_serializing`、`skip_serializing_if`。`flatten`、`serialize_with` 和其他改变结构
或算法的属性在 redacted serde 路径中产生明确编译错误。未声明 `#[redact(serde)]` 时，
serde 属性不影响 `Redact` 或 `RedactMut`。

### 11.7 显式破坏式能力

只有额外 derive `RedactMut` 才生成值替换：

```rust
pub trait RedactMut {
    fn redact_in_place(&mut self);
    fn redact_in_place_with(&mut self, policy: &RedactionPolicy);

    fn into_redacted(self) -> Self
    where
        Self: Sized;

    fn into_redacted_with(self, policy: &RedactionPolicy) -> Self
    where
        Self: Sized;

    fn to_redacted(&self) -> Self
    where
        Self: Clone + Sized;

    fn to_redacted_with(&self, policy: &RedactionPolicy) -> Self
    where
        Self: Clone + Sized;
}
```

- 不带 `_with` 的方法在调用开始时快照全局默认 policy；
- 带 `_with` 的方法使用显式 policy；
- `redact_in_place*` 永久修改当前对象；
- `into_redacted*` 消费对象并原地转换；
- `to_redacted*` clone 后修改副本，文档明确会短暂产生第二份原始敏感数据；
- 未标注与 `skip` 字段保持不变；
- `nested` 调用子对象的 `RedactMut`；
- `level` 字段使用 `policy.masking()` 并要求 `RedactValueMut`；
- `map` 字段使用完整 policy 并要求 `RedactMapValueMut`。

runtime 为 `String`、`Cow<'_, str>` 及其 `Option<T>` 实现 `RedactValueMut`，并为
`Option<T>`、`Box<T>`、`Vec<T>` 提供递归实现。借用的 `str` / `&str` 不支持原地替换。

### 11.8 编译期错误

derive 必须为以下情况给出包含类型名、字段名和修复方向的错误：

- derive 用于非 named struct；
- `#[redact(serde)]` 未启用 `qubit-redact/serde`；
- 未知 level；
- 同一字段组合 `level`、`nested`、`map` 或 `skip`；
- 重复、空或未知属性；
- redacted serde 遇到 `flatten` 或 `serialize_with`；
- `RedactMut` 字段缺少 `RedactValueMut`；
- `map` 字段不满足 `RedactMapValue` 或 `RedactMapValueMut`；
- nested 字段缺少对应 `Redact`、`RedactSerialize` 或 `RedactMut`。

生成代码使用带字段上下文的静态检查，使 trait error 尽量定位到具体字段。

## 12. 安全不变量

1. `RedactionPolicy` 构建后不可修改。
2. 全局默认只能成功安装一次，不能在运行期间替换或 reset。
3. 每个 redactor 和 redacted view 创建时快照 policy，后续行为不漂移。
4. 名称匹配不会由调用点临时覆盖。
5. `allow_exact` 不会放行 contextual suffix。
6. `HeaderValue::is_sensitive()` 不受 allow rule 影响。
7. `RedactedText` 不实现 `Display`；文本日志必须经过 `LogSafeText`。
8. HTTP Body 不存在无界入口和 raw output accessor。
9. malformed structured body 不回退输出输入内容。
10. Body 输入与输出预算由 `HttpRedactor` 强制执行。
11. `redacted()` 永远不修改领域对象。
12. 未标注字段永远不隐式递归；`nested` 和 `map` 都必须显式声明。
13. 显式 policy 会沿 `nested` 递归传播，递归途中不会重新读取全局默认。
14. `skip` 从 redacted 表示移除字段，但不修改原对象字段。
15. 基础 derive 不覆盖原对象格式化或序列化实现。
16. 敏感字段不调用原始 `Debug`、`Display` 或 `Serialize`。
17. 格式化、序列化或解析失败时不以原始值 fallback。
18. `RedactMut` 只在显式 derive 且显式调用时执行。
19. 空字符串和 `Option::None` 保持原容器语义。

## 13. 错误模型

### 13.1 构建错误

- `PolicyError`：空字段名、无效 replacement 或非法规则；
- `GlobalDefaultAlreadySet`：进程级默认已经成功安装；
- `BodyBudgetError`：输入或输出上限为零；
- `BodyCaptureError`：truncated total length 与 capture 长度矛盾；

`HttpRedactionPolicyBuilder::build()` 在接收已构建的字段 policy 和受检预算后为
infallible；URL 字符串解析失败由 redactor 内部 fail-closed。

### 13.2 不可信数据错误

日志/诊断 redaction 对数据错误 fail-closed，不要求调用方决定是否回退：

- malformed JSON/form/multipart：固定 marker；
- 非 UTF-8：固定 marker 或 binary summary；
- unsupported content type：按保守 fallback policy；
- formatter/serializer error：传播标准错误，不输出原始敏感值。

领域对象属性、结构和 trait capability 错误均在编译期失败。

## 14. 数据流

### 14.1 动态字段

```text
RedactionPolicyBuilder
  -> validate/build -> RedactionPolicy -> Redactor
  -> canonicalize -> longest rule match
  -> MaskingPolicy.mask -> RedactedText
  -> escape_for_log -> LogSafeText
```

### 14.2 Map

```text
Map<String, String>
  -> redact_map / redact_map_in_place
  -> key 作为字段名
  -> 只替换命中字段的 value
  -> 保持 Map 类型和键
```

### 14.3 HTTP Body

```text
BodyCapture + content-type
  -> apply max_input_bytes -> bounded parser
  -> structured redaction / fail-closed marker
  -> log escaping -> apply max_output_bytes
  -> BodyRedaction { LogSafeText, status, metadata }
```

### 14.4 领域对象

```text
account.redacted_with(policy)
  -> Redacted { value: &account, policy: cheap_clone }
  -> derive hook
     -> 无属性：正常格式化/序列化
     -> level：RedactValue + policy.masking()
     -> nested：子对象 redacted hook
     -> map：按 key 使用 policy redact value
     -> skip：不输出
```

领域对象的普通字段不使用字段名推断；只有显式 `map` 字段使用动态字段规则。动态 adapter
与领域对象共享 `RedactionPolicy`、`Sensitivity`、`MaskPolicy`、`MaskingPolicy`。

## 15. 旧 API 迁移

| 旧 API | 新 API |
|---|---|
| package `qubit-sanitize` | package `qubit-redact` |
| crate `qubit_sanitize` | crate `qubit_redact` |
| `SensitivityLevel` | `Sensitivity` |
| `MaskPolicies` | `MaskingPolicy` |
| `NameMatchMode` | `FieldNameMatching`，存入 policy |
| `SensitiveFields` | builder 内部规则 + policy 只读 iterator |
| `FieldSanitizePolicy` | `RedactionPolicy` |
| `FieldSanitizer` | `Redactor` |
| `sanitize_value` | `redact` |
| `sanitize_map` | `redact_map` |
| `sanitize_map_in_place` | `redact_map_in_place` |
| `exclude_sensitive_field` | `allow_exact` / `allow_suffix` |
| adapter 的 `inner_mut` / insert / extend | 构造前使用 policy builder |
| `ArgvSanitizer` | `argv::ArgvRedactor` |
| `EnvSanitizer` | `env::EnvRedactor` |
| `UrlSanitizer` | `http::HttpRedactor::redact_url` |
| `FormUrlEncodedSanitizer` | `http::HttpRedactor::redact_form` |
| `HttpHeaderSanitizer` | `http::HttpRedactor::redact_headers` |
| `HttpBodySanitizer` | `http::HttpRedactor::redact_body` |
| `BodySourceLength` | `BodyCapture::complete/truncated` |
| `BodySanitization` | `BodyRedaction` |
| `raw_content` / `into_raw_content` | 删除 |
| 旧设计 `Sanitize` derive | `Redact` |
| `SanitizeMut` | `RedactMut` |
| `Sanitized<'_, T>` | `Redacted<'_, T>` |
| `SanitizeValue` | `RedactValue` |
| `#[sanitize(mode)]` | `#[redact(mode)]` |
| 旧设计 `#[sanitize(omit)]` | `#[redact(skip)]` |
| 无对应能力 | `#[redact(map)]` |

不提供旧名称 type alias、deprecated wrapper、旧 feature alias 或 Cargo package shim。

## 16. 下游迁移

### 16.1 rs-http

- dependency 改为 `qubit-redact`，本地目录改名前 path 仍为 `../rs-sanitize`；
- `default-features = false`，启用 `features = ["http"]`；
- `LogSanitizePolicy` 破坏性改名为不可变 `LogRedactionPolicy`，由 builder 最终生成完整
  header/query/body policy；
- `LogSanitizer` 改名为 `LogRedactor`，内部只持有一个 `HttpRedactor`；
- `BodyPreview` 继续表达调用点较低的展示限额，`BodyBudget` 独立表达不可绕过的库级硬
  上限，effective limit 取两者中更严格的一层；
- body 日志只消费 `BodyRedaction` 的 `Display` / `LogSafeText`；
- 删除手工 merge 默认字段、custom fields 和 exclusions。
- `sanitize` module/type/method、`log_sanitize_policy` 字段和 `log_sanitize` 配置 section
  全部改为 `redact` / `log_redaction`，不提供兼容读取。

### 16.2 rs-command

- dependency 改为 `qubit-redact`，关闭默认 feature；
- diagnostic policy 在 runner 构建阶段完成；
- argv 使用 `ArgvItem::plain/sensitive`，shell payload 明确标为敏感；
- env 使用 `EnvRedactor`；
- stdout/stderr 的 `redacted_debug` 能力保留。

### 16.3 rs-config

- dependency 改为 `qubit-redact`，关闭默认 feature；
- 迁移 `redacted_debug` import；
- 非 UTF-8 env 诊断改用 `EnvRedactor`；
- 不启用 derive、serde 或 http。

### 16.4 主仓库

- package、crate、文档、README、badge、doctest 和 fuzz package 全部改名；
- 所有旧测试迁移到新 API；
- 新增 `derive/` crate 和领域对象测试；
- CI、coverage、align scripts 覆盖 runtime 与 derive workspace。

## 17. 源码组织

public struct、enum、trait 遵循 type-per-file；内部 helper 置于 `internal`：

```text
src/
├── lib.rs
├── policy/
│   ├── redaction_policy.rs
│   ├── redaction_policy_builder.rs
│   ├── policy_error.rs
│   ├── sensitivity.rs
│   ├── field_name_matching.rs
│   ├── sensitive_field_preset.rs
│   ├── mask_policy.rs
│   ├── masking_policy.rs
│   └── internal/
├── text/
│   ├── redacted_text.rs
│   ├── log_safe_text.rs
│   └── log_escape.rs
├── redactor.rs
├── argv/
├── env/
├── domain/
│   ├── redact.rs
│   ├── redact_mut.rs
│   ├── redact_value.rs
│   ├── redact_value_mut.rs
│   ├── redact_map_value.rs
│   ├── redact_map_value_mut.rs
│   ├── redacted.rs
│   ├── redacted_value.rs
│   └── redacted_map.rs
└── http/
    ├── http_redaction_policy.rs
    ├── http_redaction_policy_builder.rs
    ├── http_redactor.rs
    ├── body_budget.rs
    ├── body_capture.rs
    ├── body_redaction.rs
    └── internal/

derive/src/
├── lib.rs
├── redact_derive.rs
├── redact_mut_derive.rs
├── attributes.rs
├── serde_attributes.rs
└── internal/
```

外部测试目录镜像源码结构；proc-macro compile fixtures 位于
`derive/tests/fixtures/`。

## 18. 测试设计

实现采用 test-first：每项行为先写目标明确的失败测试并确认失败原因，再写最小实现。

### 18.1 policy、Redactor 与文本

- 默认字段及全部 preset；
- `RedactionPolicy::default()`、`standard()` 和全局 fallback；
- 全局默认只能设置一次，且已创建对象保持原 policy 快照；
- Exact 与 token suffix；
- `allow_exact` 不影响 contextual suffix；
- `allow_suffix` 的显式宽泛行为；
- 最长候选优先；
- `raise` 不降级、`override_level` 可降级；
- 非法 builder 输入；
- 四级 sensitivity、默认与自定义 masking；
- ASCII、Unicode、空字符串；
- `RedactedText` 无 `Display` 的 compile-fail；
- `LogSafeText` 的控制字符、line separator 和 bidi 转义；
- `HashMap` / `BTreeMap` copy 与 in-place；
- property test 覆盖 canonicalization、确定性和命中结果不含原始 secret。

### 18.2 argv/env

- 显式 plain/sensitive item 与 shell payload；
- heuristic 的 option、assignment 和 `--`；
- 非 UTF-8 fail-closed；
- env pair、OS pair、assignment；
- `Display` 中无原始 secret 或日志控制字符。

### 18.3 HTTP

- URL userinfo/path/query/fragment 和 malformed input；
- Header name policy、native sensitive flag、非 UTF-8；
- JSON、NDJSON、form、multipart、text、binary；
- unkeyed JSON、file part、malformed structured input；
- complete/truncated capture invariant；
- 输入预算只处理前缀；
- 输出预算在日志转义后执行；
- metadata 与 truncation suffix；
- public API 不存在 raw body accessor；
- 迁移现有 proptest 与三个 fuzz target。

### 18.4 领域对象 runtime

- 四级 sensitivity 与自定义 `MaskingPolicy`；
- `String`、`str`、`Cow<str>`、`Option`；
- 未标注、level、nested、map、skip；
- `HashMap` / `BTreeMap` 字段的惰性 view 与原地 redaction；
- `redacted()` 使用全局默认快照，`redacted_with()` 使用显式 policy；
- 显式 policy 在 nested 对象和 Map 字段中保持一致；
- `Option`、`Box`、`Vec` 与泛型 named struct；
- Debug、pretty Debug、日志安全 Display；
- wrapper 使用后原对象不变；
- 敏感字段不调用原始格式化或序列化；
- `redact_in_place`、`into_redacted`、`to_redacted`；
- 自定义 `RedactValue` / `RedactValueMut`。

### 18.5 serde 与 proc macro

- 基础对象、Some/None、嵌套对象；
- rename、skip、skip_if；
- 原始与 redacted serialization 并存；
- serializer error 不泄漏原始值；
- named struct、泛型、生命周期、where clause；
- 非 named struct、enum、非法 level、冲突属性；
- unsupported serde attribute；
- dependency rename；
- `Redact` 成功而 `RedactMut` 因借用字段失败；
- 错误消息包含类型名、字段名和修复方向。

### 18.6 feature 与下游矩阵

至少执行：

```text
cargo test --no-default-features
cargo test --no-default-features --features derive
cargo test --no-default-features --features serde
cargo test --no-default-features --features derive,serde
cargo test --no-default-features --features http
cargo test --all-features
cargo test --manifest-path derive/Cargo.toml
```

同时执行主仓库 `align-ci.sh`、`ci-check.sh`、`coverage.sh json`，以及三个下游各自规定的
fmt、clippy、test 和 feature 检查。doctest、property test 及 fuzz target 必须成功编译。

## 19. 性能约束

1. `Redactor`、`RedactionPolicy`、`MaskingPolicy` clone 为常量成本。
2. 未命中字段返回 borrowed `RedactedText`，不分配。
3. Map copy 只因 owned 结果分配；in-place 只替换敏感值。
4. Body parser 不读取超过输入预算的字节。
5. Body 日志输出（包含固定 truncation marker）不超过输出预算。
6. `Redacted<'_, T>` 创建不读取字段、不 clone 对象，只 cheap-clone policy。
7. `RedactedMap` 按输出迭代惰性处理，不为非破坏式 view 复制整张 Map。
8. `to_redacted` 的 clone 成本写入文档；性能路径使用 `into_redacted` 或 view。
9. 完成后为 field lookup、Map、HTTP Body 增加 benchmark；优化以基准为依据。

## 20. 文档与发布

1. README 明确该库按显式规则 redacts 已知敏感内容，不是 secret scanner。
2. README 示例覆盖 Map、自定义 policy、日志安全文本、HTTP 和 derive。
3. crate rustdoc 明确 `RedactedText` / `LogSafeText` 边界。
4. HTTP 文档强调 Body 只用于有界日志/诊断预览。
5. derive 文档列出支持的结构、属性和限制。
6. CHANGELOG 将包改名和旧 API 删除标为 breaking。
7. 先发布 `qubit-redact-derive 0.1.0`，再发布 `qubit-redact 0.1.0`。
8. GitHub 改名前保持当前有效 URL；改名后单独更新 metadata 和 badge。

## 21. 实施拆分

该设计覆盖两个可独立审查、顺序执行的子项目，不写成一个不可控的大型实施批次：

1. **Runtime 与下游迁移计划**
   - 包和 crate 改名；
   - policy、Redactor、文本类型、Map、argv、env；
   - HTTP feature、有界 Body；
   - rs-http、rs-command、rs-config 同步迁移；
   - 迁移原有 tests、proptest 与 fuzz targets。
2. **领域对象与发布收尾计划**
   - workspace 和 `qubit-redact-derive`；
   - `Redact`、`RedactMut`、serde runtime；
   - compile-pass/compile-fail fixtures；
   - README、rustdoc、CHANGELOG、feature matrix 和全仓最终验证。

第二个计划依赖第一个计划稳定后的 `Sensitivity`、`MaskingPolicy`、`LogSafeText`。两个
计划都遵循 TDD；中间状态不发布，最终验收仍要求四个仓库和全部 feature 一起通过。

## 22. 验收标准

1. `qubit-redact --no-default-features` 无外部 runtime dependency。
2. `Redactor::default()` 可脱敏 HashMap/BTreeMap 中的预定义字段。
3. `RedactionPolicy` 实现 `Default`，全局默认可在启动阶段成功安装一次。
4. builder 可添加、提高、覆盖和显式放行字段。
5. 名称匹配只由 policy 决定。
6. `allow_exact` 不产生 contextual suffix 放行。
7. `RedactedText` 不能误作 Display 日志文本；`LogSafeText` 可安全输出。
8. HTTP feature 默认关闭，启用后 URL、form、Header、Body 能力完整。
9. HTTP Body 无无界或 raw API，输入/输出预算由库强制。
10. `#[derive(Redact)]` 可生成领域对象非破坏式视图。
11. `#[redact(map)]` 可使用全局或显式 policy 脱敏 Map value。
12. 未标注字段不递归；`nested`、`map`、`skip` 语义互斥且明确。
13. 原对象与 redacted view 的格式化、序列化互不干扰。
14. 敏感领域字段不调用自身 Debug、Display 或 Serialize。
15. `RedactMut` 只通过显式 derive 提供。
16. 非法 derive 输入产生定向编译错误。
17. `rs-http`、`rs-command`、`rs-config` 全部迁移。
18. 不存在旧包名、crate 名、type alias、deprecated façade 或 feature alias。
19. runtime、derive、feature matrix、doctest、property tests、fuzz compile 及三个下游验证
    全部通过。

## 23. 已确认决策

1. 使用 `redact` 而非 `sanitize`。
2. crate 改名为 `qubit-redact` / `qubit_redact`。
3. HTTP 保留在主 crate，通过默认关闭的 `http` feature 发布。
4. HTTP Body 只提供有界日志/诊断预览。
5. 四个仓库同轮迁移。
6. 不保留兼容层。
7. Map、预定义字段和遮盖能力完整保留。
8. 领域对象 derive 纳入本次重构并统一采用 Redact 术语。
9. `RedactionPolicy` 实现 Default，并支持一次性安装进程级默认。
10. `#[redact(map)]` 使用 view 的全局默认快照或显式 policy。
11. 删除 `omit`，使用语义明确的 `#[redact(skip)]`。
