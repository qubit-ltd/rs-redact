# 用户指南

除非已经显式构建并注入应用自己的 `RedactionPolicy`，否则应选用 `Redactor::strict()`。
`Redactor` 持有不可变 policy 快照；其 `session()` 创建可复用且共享该快照的
`RedactionSession`。

所有聚合 session API（`literal`、`field`、`value`、`argv`、`env`、`process`、`json`、
`http`、`uri`）写入一个组合结果。所有单项 API（`redact_field`、`redact_value` 和各
format 的 `redact_*`）返回不透明 handle。handle 不可转为文本，只能由同一轮
transaction 的 `finish()` 结果解析。

字面量、脱敏值、转义、标记以及每一种 format 的所有输出字节，都只会在同一个 session
输出预算中计费一次。预算耗尽后，后续 accessor 和 adapter closure 都不会执行。用户的
脱敏代码发生 panic 时，当前 transaction 会被丢弃、session 被重置、panic 继续向外传播；
该轮不会发布任何结果。

`RedactedText` 是最终安全的脱敏文本。`RedactionOutput` 增加单项 summary。
`RedactionSessionOutput` 提供聚合文本、聚合 summary 和 handle 解析。

derive 的 domain 类型中，未标注的字段刻意不脱敏。每个敏感字段都必须使用
`#[redact(...)]` 明确标注。writer 的 `literal` 仅用于程序字面量，`unredacted` 仅用于
可信的动态内容。
