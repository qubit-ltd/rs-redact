# rs-redact 与 rs-redact-derive 重构设计

日期：2026-08-23

## 1. 目标与范围

本次重构从实际使用场景出发，将 `rs-redact` 收敛为“借用原值并安全输出”的系统，不再提供把对象自身修改或克隆成脱敏对象的能力。

范围包括：

- 简化 `rs-redact` 的领域 trait；
- 删除 mutable/object-transform API；
- 重构 `rs-redact-derive`，删除独立 derive-core crate；
- 修正结构化 Serde、JSON、字段格式化和 summary 契约；
- 修改 `rs-model-derive`，让 `#[Model(redact)]` 委托公开的 Redact derive；
- 验证 `rs-model-metadata` 与 `rs-platform` 下游。

## 2. 核心运行时 API

公开领域 trait 只保留一个方法：

```rust
pub trait Redact {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);
}
```

删除：

- `RedactMut`；
- `RedactValueMut`；
- `RedactMapValueMut`；
- `redact_in_place[_with]()`；
- `to_redacted[_with]()`；
- `into_redacted[_with]()`；
- trait 和 derive 生成的 `redacted[_with]()`、`inspected[_with]()` 便利方法。

`Redactor` 继续作为执行入口，保留通用 `redact<T: Redact>()`、`inspect<T: Redact>()` 以及所有格式专用的 `redact_xxx()`、`inspect_xxx()`。

不创建脱敏后的 `Self`。日志和诊断使用 writer 输出；REST 等结构化传输使用 `#[redact(serde)]`。

## 3. 全局禁用脱敏

`RedactionPolicy` 内部增加 `disabled: bool`，不增加 enum。公开 API：

```rust
impl RedactionPolicy {
    pub fn disabled() -> Self;
    pub const fn is_disabled(&self) -> bool;
    pub fn set_disabled(&mut self, disabled: bool) -> &mut Self;
}
```

`RedactionPolicy::disabled()` 返回带标准规则、预算和限制、但 `disabled == true` 的 policy。`standard()`、`strict()` 和 builder 默认产生 `disabled == false` 的 policy。`Clone`、`PartialEq`、`Eq`、`to_builder()` 和 `build()` 必须保留该状态。

典型启动方式：

```rust
if config.disable_redaction {
    let _ = Redactor::replace_application_default(
        Redactor::new(RedactionPolicy::disabled()),
    );
}
```

该开关在应用初始化阶段设置，整个进程生命周期不再恢复。禁用时，整个 `rs-redact` 的 scalar、domain、argv、env、process、JSON、HTTP、URI 等脱敏入口都原样输出。

禁用脱敏不等于禁用资源与输出安全边界。输入、输出、深度、节点预算，日志控制字符转义，以及源数据已经截断的事实继续生效。

derive 字段上的 `level`、`nested`、`map`、`json`、`skip` 在禁用模式下全部视为不存在，因此 `#[redact(skip)]` 字段恢复输出。普通 `#[serde(skip)]`、`skip_serializing` 等 Serde 规则不受影响。

`RedactionSummary` 增加 `is_redaction_disabled()`。inspection 在该模式下返回明确的 disabled 状态，不能把原始输出误判为已安全脱敏。

## 4. derive 属性语义

容器级属性只保留：

```rust
#[redact(debug)]
#[redact(display)]
#[redact(serde)]
```

字段级属性只保留：

```rust
#[redact(level = "low|medium|high|secret")]
#[redact(nested)]
#[redact(map)]
#[redact(json)]
#[redact(skip)]
```

删除：

```rust
#[redact(plain)]
#[redact(no_mut)]
#[redact(require_explicit)]
```

每个字段最多选择一种模式；重复、冲突、未知属性均产生定位到字段的编译错误。

启用脱敏时：

| 字段模式 | 行为 |
| --- | --- |
| 无标记 | 当前类型不额外脱敏，使用字段类型自身的普通输出 trait |
| `level` | 按声明的最低等级和 policy 的最终等级逐叶子 mask |
| `nested` | 共享当前 policy、writer、预算和 summary，递归调用 `Redact` |
| `map` | 按字符串 key 查询 policy，并处理相应 value |
| `json` | 解析字符串中的 JSON，按对象 key 递归处理 |
| `skip` | 完全省略，且不访问字段值 |

无标记字段不会根据其类型是否实现 `Redact` 自动递归。Rust 过程宏无法可靠实施“实现了 Redact 就递归，否则回退普通输出”的条件分派。需要递归时必须显式使用 `nested`。

无标记字段调用其自身普通 `Debug`、`Display` 或 `Serialize`。如果字段类型自己通过 `#[redact(debug)]` 或 `#[redact(serde)]` 接管了这些 trait，其类型级安全契约仍然生效；父类型不会绕过它。

## 5. 字段 capability

### 5.1 level

基础标量包括：

- `String`、`&str`、`Cow<'_, str>`、`char`、`bool`；
- 所有有符号与无符号整数；
- `f32`、`f64`；
- 启用 `serde` feature 时的 `bigdecimal::BigDecimal`，用于保持下游模型的 decimal
  字段与结构化 Serde capability 一致。

递归规则：

```text
LevelValue :=
    Scalar
  | Option<LevelValue>
  | Vec<LevelValue>
  | [LevelValue; N]
  | (LevelValue, ...)
```

tuple 支持 1 到 12 个元素。叶子不得是 struct、enum、map 或其他对象。类型别名按实际类型自然生效。

集合逐叶子 mask 并保持 `Option`、Vec、数组和 tuple 结构。`Low`、`Medium` 对叶子执行有界格式化后 mask；`High`、`Secret` 不调用叶子的 `Debug`、`Display` 或 `Serialize`，直接输出 opaque mask。为保持结构，仍会观察容器状态、长度和 tuple 形状。

### 5.2 nested

递归规则：

```text
NestedValue :=
    T: Redact
  | Option<NestedValue>
  | Vec<NestedValue>
  | [NestedValue; N]
  | (NestedValue, ...)
```

运行时为这些容器实现 `Redact`，叶子调用自身 `write_redacted()`。不实现 `Redact` 的叶子导致字段级编译错误。

### 5.3 map

支持：

```text
HashMap<StringKey, LevelValue>
BTreeMap<StringKey, LevelValue>
Option<HashMap<StringKey, LevelValue>>
Option<BTreeMap<StringKey, LevelValue>>
```

`StringKey` 支持 `String`、`&str`、`Cow<'_, str>`。key 原样输出；命中 policy 时 value 按相应等级逐叶子 mask，未命中时 value 原样输出。

不把 `Vec<(K, V)>` 或任意 `IntoIterator` 当作 map。第三方 map 以后可通过明确 feature 增加受控支持。

### 5.4 json

支持：

```text
String
&str
Cow<'_, str>
Option<String>
Option<&str>
Option<Cow<'_, str>>
```

合法 JSON 按对象 key 递归处理。非法、输入超限或结构超限时，在启用模式下不输出任何原始片段，整个字段 opaque mask。禁用模式下不解析，直接输出原始字符串。

字段本身仍是字符串，Serde 不会把 JSON 字符串擅自改成嵌套对象。

### 5.5 capability 实现

运行时提供公开但 `#[doc(hidden)]` 的 derive 支撑 capability。`RedactLevelValue`、`RedactMapValue`、`RedactJsonValue` 使用私有 supertrait 密封，只允许 runtime 为受支持类型实现；结构化 `RedactSerialize` 不能密封，因为下游 derive 必须为用户类型生成实现。它们用于可靠的 trait-bound 诊断，不是面向普通用户的领域 API。

## 6. writer 与 inspection

derive 只生成结构访问代码，所有 policy 判断集中在 runtime writer。字段 scope 提供对应的内部操作：

```rust
fields.unmarked(name, || &self.field);
fields.sensitive(level, name, || &self.field);
fields.nested(name, &self.field);
fields.map(name, &self.field);
fields.json(name, &self.field);
fields.skipped(name, || &self.field);
```

`skipped` 必须保留惰性闭包：启用时不访问字段，禁用时恢复原值。

inspection 不格式化字段：

- `level` 记录最终 sensitivity；
- `nested` 递归；
- `map` 按 key 检查；
- `json` 按 JSON key 检查；
- 无标记与启用模式下的 `skip` 不产生敏感观察；
- policy 禁用时返回 disabled 状态。

## 7. Debug 与 Display

`#[redact(debug)]`、`#[redact(display)]` 直接实现原类型对应 trait，普通格式化使用 application-default policy：

```rust
format!("{value:?}");
format!("{value}");
```

二者均通过 `write_redacted()` 和受预算约束的 writer 输出，不生成脱敏对象。类型不能同时自行实现或 derive 相同的格式化 trait；冲突通过编译错误报告。

## 8. 结构化 Serde

`#[redact(serde)]` 直接接管原类型的 `Serialize`。调用：

```rust
serde_json::to_string(&value)?;
```

必须产生真正的结构化数据，不能把 `Redactor::redact()` 产生的调试文本序列化成单个 JSON string。

保留：

- struct、tuple、enum wire shape；
- external、internal、adjacent、untagged enum 表示；
- `rename`、`rename_all`、`rename_all_fields`；
- Serde 自身的 `skip`、`skip_serializing`；
- 已确认的 `skip_serializing_if` 行为。

不生成 `Deserialize`。调用方可以独立 derive `Deserialize`，但不能再同时普通 derive `Serialize`。

无标记字段使用普通 `Serialize`。masked 标量叶子统一序列化为字符串；`Option::None` 保持 `null`。禁用模式恢复原始标量 JSON 类型。

`with`、`serialize_with` 只允许无标记字段。与 `level`、`nested`、`map`、`json` 同时使用时产生编译错误；在 `skip` 字段上可接受但启用模式下不调用。

`skip_serializing_if` 对原始字段执行：

1. predicate 返回 `true` 时省略；
2. 返回 `false` 时再执行字段模式；
3. `redact(skip)` 在启用模式下无条件省略且不调用 predicate；
4. 禁用模式下 `redact(skip)` 视为不存在，此时恢复执行 predicate。

predicate 会接收原始字段引用，即使 sensitivity 是 `High` 或 `Secret`。这是类型作者显式选择的 wire contract。

启用 Serde 的 derive 还生成 `#[doc(hidden)]` 的结构化 `RedactSerialize` capability。父类型的 `nested` 字段在结构化 Serde 中要求子类型同样启用 `#[redact(serde)]`，并通过隐藏 capability 共享父级 policy，而不是把脱敏文本塞进 JSON。

直接 Serde 没有 `RedactionSummary` 返回通道。非法 JSON 等情况仍 fail-closed，但只有 `write_redacted()` 路径公开记录具体 summary 原因。

通用 Serde 面向任意 serializer，无法在不缓冲完整编码的情况下计算最终输出字节数。因此：

- `write_redacted()` 严格执行输入、输出、深度和节点预算；
- 结构化脱敏 Serde 执行输入、深度和节点准入；
- JSON 字符串超限时整体 opaque mask；
- 最终 JSON、CBOR 等编码字节数由 serializer 或 HTTP body 层限制；
- 无标记字段走普通 `Serialize`，不受 redaction traversal budget 管理；
- 不为了输出字节计数构造完整 `serde_json::Value` 或通用中间 AST。

## 9. 通用字段脱敏 API

不增加 `redact_debug_xxx()`、`redact_display_xxx()` 方法族。现有以下 API 改为接受惰性的 `Display` 值：

```rust
Redactor::redact_field()
RedactionBatch::redact_field()
RedactedTextComposer::field()
```

仅实现 `Debug` 的值可以通过惰性的 `fmt::Arguments` 使用：

```rust
redactor.redact_field("request", format_args!("{request:?}"));
```

执行顺序：先分类；`High`、`Secret` 不触发 `fmt`；`Low`、`Medium` 有界格式化后 mask；pass-through 也有界格式化；超限时 fail-closed。

## 10. JSON runtime API

保留 JSON 文本 API，并新增借用的 `serde_json::Value` API：

```rust
redactor.redact_json_value(&value);
redactor.inspect_json_value(&value);
batch.redact_json_value(&value);
writer.value(&value);
fields.json_value("payload", &value);
```

借用 Value 路径不 clone、不 `to_string()`、不修改调用方对象。

JSON 文本只解析一次。解析 visitor 在输入、深度和节点准入的同时构建 admitted tree；renderer 与 inspection 共用该模型。非法或超限文本整体 opaque mask。

## 11. Summary 契约

不再要求所有调用方无条件检查 summary。

policy 启用时，`Complete`、`Truncated`、`Exhausted` 的文本都必须保持保密安全。只有需要完整性、截断原因或审计信息的调用方才检查 summary。调用方不得解析 `<truncated>` 等文本 marker 推断状态。

`inspect_xxx()` 用于安全决策时，仍必须对不确定结果 fail-closed。

policy 禁用时，输出有意包含原值；summary 的 `is_redaction_disabled()` 记录该事实。这是启动配置，不是处理失败。

## 12. rs-redact-derive 重构

删除整个 `rs-redact-derive/core/` 和 `qubit-redact-derive-core` package。Redact 展开实现只保留一份，直接放入 `rs-redact-derive/src/`。

目标结构：

```text
src/
├── lib.rs
├── attributes/
├── model/
├── expand/
├── serde/
└── runtime_path.rs
```

固定处理流程：

```text
DeriveInput
  -> 严格解析 container/field/serde 属性
  -> 建立统一 model
  -> 验证属性组合
  -> 生成 Redact
  -> 可选生成 Debug/Display
  -> 可选生成 Serialize 与隐藏 capability
```

不再保留 immutable/mutable 双 expansion、`RedactOptions`、`expand_with_options()`、mutable helper、`no_mut` 分支，以及 derive 生成的 inherent 便利方法。

## 13. derive 宏重导出

`qubit-redact` 增加默认启用的 `derive` feature：

```toml
[features]
default = ["serde", "derive"]
derive = ["dep:qubit-redact-derive"]
```

并重导出宏：

```rust
#[cfg(feature = "derive")]
pub use qubit_redact_derive::Redact;
```

trait 与 derive 宏位于不同命名空间，可以同名。普通用户只需依赖 `qubit-redact`：

```rust
use qubit_redact::Redact;

#[derive(Redact)]
struct Request {
    #[redact(level = "secret")]
    password: String,
}
```

`default-features = false` 的调用方如需宏，必须显式启用 `derive`。使用 `#[redact(serde)]` 时，调用方仍需直接依赖 `serde`。

这不形成普通依赖循环：`qubit-redact-derive` 不以普通依赖方式依赖 runtime；其 runtime 依赖仅用于测试，并保持 `default-features = false`，不重新启用自身 derive。

## 14. rs-model-derive 委托

当前 `rs-model-derive` 直接依赖 `qubit-redact-derive-core` 并调用 `expand_with_options()`。该依赖具有真实用途，不能在不迁移调用方的情况下直接删除。

迁移后，`#[Model(redact)]` 不再调用宏内部 expansion，而是输出公开 derive：

```rust
#[derive(::qubit_redact::Redact)]
#[redact(debug, display, serde)]
```

具体容器选项继续根据 `Model` 的 `no_debug`、`no_display`、`no_serialize` 决定。字段级 `#[redact(...)]` 保留给正式 Redact derive 解析，不再提前删除。

`rs-model-derive` 通过 `proc_macro_crate` 解析调用方重命名后的 `qubit-redact` 路径。它不再理解 Redact 的 capability、writer 或 Serde 展开细节。

## 15. 下游影响

必须同步验证：

1. `rs-redact-derive`；
2. `rs-redact`；
3. `rs-model-derive`；
4. `rs-model-metadata`；
5. `rs-platform` 全 workspace。

复核发现：

- `rs-model-derive` 当前直接依赖 derive-core；
- `rs-platform` 约有 44 个源码文件、148 处 Redact 相关引用；
- 现有 `level` 字段主要为 `String`、`Option<String>`；
- 现有 `nested` 字段使用 `Option<T>`、Vec、`Option<Vec<T>>` 等已纳入的新能力；
- `ErrorInfo.params` 为 `Option<BTreeMap<String, Option<String>>>`，符合 map 规则；
- 至少一处测试显式依赖 `RedactMut` 和 `redact_in_place()`，需改为验证借用输出不修改原对象。

不能把下游影响描述为仅限两个 redact crate 的测试。

## 16. 测试与验证

### 16.1 derive 测试分层

- 模块单元测试：属性解析、model、命名和 token expansion；
- trybuild：属性冲突、类型 capability、Serde adapter 冲突、feature/依赖缺失、泛型 bounds；
- runtime：struct、enum、tuple、unit、递归容器、map、JSON，以及 enabled/disabled 对照；
- Serde wire-shape：rename、enum tagging、`skip_serializing_if`、redact skip 恢复、逐叶子 string mask。

当前从 core crate 外部导入内部函数的测试改为模块单元测试。已有可靠 fixture 尽量迁移；mutable、plain、require-explicit fixture 删除或改写。

### 16.2 安全回归

- `High`、`Secret` 不触发叶子格式化或敏感字段 Serde adapter；
- enabled 模式下截断、超限、非法 JSON 不泄漏原文；
- disabled 模式下所有 redaction 入口恢复原值；
- disabled 模式下 `redact(skip)` 恢复、`serde(skip)` 不恢复；
- nested 共享 policy、预算和 summary；
- map 逐 key 分类，不能把整个 map 固定当作 Low 字段；
- 结构化 Serde 不退化为调试字符串；
- inspection 永不渲染字段值；
- application-default 替换继续提供完整原子快照。

### 16.3 工程验证

- 所有 feature 组合执行 `cargo check`；
- `cargo test`、Clippy、Rustdoc；
- trybuild stderr 人工复核；
- 中英文文档示例作为可编译测试；
- `rs-model-derive` 和 `rs-platform` workspace 全量验证。

`rs-redact-derive` 测试依赖 runtime 时保持 `default-features = false`，避免测试路径启用自身 derive。`rs-model-derive` 测试 runtime 依赖启用 `derive` 与 `serde`。

## 17. 文档要求

更新：

- `Redact`、`RedactionWriter`、`Redactor`、`RedactionPolicy` Rustdoc；
- derive 宏和每种属性的 Rustdoc；
- 中英文 README；
- 中英文用户手册。

示例覆盖非字符串惰性格式化、High/Secret 不调用 fmt、nested 容器、map、JSON、结构化 REST Serde、全局禁用模式、summary 检查要求，以及 enabled/disabled 对照。

## 18. 发布顺序

同步完成代码和下游验证后：

1. 发布 `qubit-redact-derive`；
2. 发布默认重导出 derive 的 `qubit-redact`；
3. 更新并发布/集成 `rs-model-derive`；
4. 更新 `rs-model-metadata` 与 `rs-platform`。

新旧 runtime 与 derive 不应交叉使用；版本约束必须保证兼容组合。
