# rs-redact 事务化重构验收记录

日期：2026-08-21

## 范围

本记录只覆盖 `rs-redact`。`rs-redact-derive` 和七个直接下游尚未迁移，按本轮明确范围不纳入完成判定，也未修改。

## 架构闭环

- `TransactionState` 只保存一个 `RedactionBudget`、一个 `OutputBuffer`、`Vec<ItemRange>`、统一 summary 状态和设计规定的 `TransactionPhase`；phase 只能在 `Active` 与 `OutputExhausted` 间单向推进。
- aggregate 与 handle 文本先写入 transaction-owned arena，最终 `RedactionOutput` 和 `RedactedText` 只在 publication 路径创建。
- argv、env、process、JSON、HTTP 和 URI adapter 只返回 crate-private `RenderedOperation`，禁止创建最终 output、summary 或 safe-text wrapper。
- `RedactionWriter` 已删除兼容 `list`、设计外的公开 `unit` 和 policy escape hatch；根 writer 的公开方法严格收敛到设计清单，field、sequence、map closure 分别使用 `RedactionFields`、`RedactionItems`、`RedactionEntries`。
- exact-fill 后的下一次操作会把 transaction 单调推进为 `Exhausted`，并且不会进入 accessor、parser 或 adapter closure。

以上约束由 `tests/runtime_architecture_tests.rs` 的四个 source-level 回归测试固定。

## 强制回归矩阵

| 契约 | rs-redact 覆盖 | 状态 |
|---|---|---|
| Session 复用 | `test_chain_and_statement_aggregate_calls_are_equivalent`、`test_three_consecutive_finishes_publish_independent_transactions` | 通过 |
| 原子发布 | `test_finish_publishes_items_and_resets_the_reusable_session`、`finished_session_resets_and_old_handles_cannot_cross_transactions` | 通过 |
| Panic | `test_panic_rolls_back_the_active_transaction_and_resets_the_session`、`test_panic_after_partial_domain_write_discards_everything`、`test_panic_rollback_invalidates_handles_from_the_discarded_transaction` | 通过 |
| 聚合/单项隔离 | `transaction_aggregates_literal_field_and_value_and_publishes_handles_on_finish`、`test_value_handle_keeps_its_operation_summary_without_double_charging` | 通过 |
| 输出预算 | `test_runtime_entry_points_share_the_output_budget_matrix`、`test_every_adjacent_operation_pair_closes_the_shared_budget_chain` | 通过 |
| 输入/结构预算 | `test_field_entry_points_share_input_admission`、`test_format_adapters_share_the_transaction_structural_budget`、HTTP/JSON/URI collection/depth tests | 通过 |
| 耗尽短路 | `test_exhausted_output_does_not_invoke_later_adapter_closures`、`test_exhausted_output_does_not_consume_later_handle_iterators`、`test_process_handle_exact_argv_fill_does_not_pull_environment_iterator`、相邻预算链哨兵 | 通过 |
| Summary | `summaries_keep_completion_reason_and_usage_machine_readable`、HTTP source truncation usage tests、重复 reason tests | 通过 |
| Domain writer | writer sensitivity、unredacted、nested、output limit tests；scope source-level contract test | 通过 |
| Formats | 六类 format 的 aggregate、handle、convenience 组合测试 | 通过 |
| 默认实例 | application-default replacement、snapshot isolation、并发完整快照测试 | 通过 |
| 公开面 | `public_api_tests`、compile-fail doctests、固定 root writer 方法集与旧架构零残留扫描 | 通过 |
| Derive | 属于本轮明确排除的 `rs-redact-derive` 范围 | 不适用 |

全 format 相邻链严格按计划顺序覆盖：

```text
literal → field → value → JSON → HTTP URL → HTTP body → URI → argv → env → process
```

九个相邻 pair 均由同一参数化测试验证：前一项精确用尽 output budget，后一项进入耗尽短路；可观测的 accessor、parser、adapter closure 均不得执行，耗尽后的第三项 closure 也不得执行。

## 测试替换映射

本轮未删除测试文件或测试用例。行为调整和替代关系如下：

| 原覆盖 | 新覆盖或调整 | 保留契约 |
|---|---|---|
| `exact_output_budget_fill_skips_later_argv_adapter_work` 原先只断言跳过 | 同名测试改为断言 `Exhausted` 和 `OutputLimitReached`；相邻链测试覆盖全部入口 | exact-fill 后尝试下一项必须显式耗尽 |
| `test_domain_rendering_uses_one_bounded_transaction_output_budget` 原先期望 `Truncated` | 同名测试改为期望第二次操作触发 `Exhausted` | completion 单调且后续操作不可被静默吞掉 |
| writer nested-list 形状测试使用兼容 `list` | 同名 writer shape 测试改用 `sequence` 和独立 item scope | structured shape 与共享 transaction |
| 无架构防回归 | `runtime_architecture_tests` 四项约束 | 禁止 adapter 最终模型、双状态、旧 alias、scope 越权 |
| 入口预算抽样 | `test_every_adjacent_operation_pair_closes_the_shared_budget_chain` | 计划规定的九个相邻 pair 完整闭环 |
| process handle 内部 argv 精确填满后仍拉取 env iterator | `test_process_handle_exact_argv_fill_does_not_pull_environment_iterator` | 内部 successor 也必须在 `OutputExhausted` 前短路且组合 item fail-closed |

## 质量门禁证据

以下命令均于 2026-08-21 在 `rs-redact` 根目录通过：

```text
cargo +nightly-2026-06-05 fmt --manifest-path Cargo.toml -- --check --config-path .rs-ci/rustfmt.toml
cargo check --all-targets --all-features
cargo test --all-features
cargo test --no-default-features
cargo +nightly-2026-06-05 clippy --all-targets --all-features -- -D warnings
cargo doc --all-features --no-deps
RS_CI_PROJECT_ROOT="$PWD" ./.rs-ci/style-check.sh
git diff --check
```

Fuzz 冒烟也按计划时长通过。执行环境受 ptrace 管理，LeakSanitizer 无法工作，因此显式设置 `ASAN_OPTIONS=detect_leaks=0`；AddressSanitizer 的其余检查保持开启：

```text
command_inputs: 60 秒，195693 runs
direct_inputs: 60 秒，219818 runs
transaction_sequences: 120 秒，235357 runs
```
