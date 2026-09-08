---
verdict: ready
summary: "4 个任务的执行计划已通过独立 reviewer 与修订后 checker；边界保持在 Keystone 与部署。"
constraints:
  - "状态变更与 durable event 同事务，失败整体回滚"
  - "introspection 必须 INTERNAL_TLS + gateway Basic 双门"
  - "首个 principal 无 credential、scope、grant"
decisions:
  - "执行 TASK-001 至 TASK-004"
concerns:
  - "部署必须 single-active，禁止 mixed-version writer"
next:
  - "execute"
details:
  reviewer_verdict: PASS_WITH_CONCERNS
  final_plan_check: PASS
---
## 摘要

计划由独立 planner 生成，经外部 reviewer 找到 6 个具体缺口并全部修复，最终 `plan-check.json` 为 `PASS`。

## 结论/Verdict

可以执行。4 个任务依次覆盖 schema/Store、operator CLI、内部 introspection、构建发布与首个零授权 principal 创建。

## 讨论/复盘

首个实例只创建身份记录，不提前签发 credential；每应用身份、Verdict service lifecycle 与 Rikune 消费接入继续保持 deferred。

## 产物

- `outputs/plan.json`
- `outputs/tasks/TASK-001.json` 至 `TASK-004.json`
- `outputs/waves.json`
- `outputs/dependency-graph.json`
- `outputs/collision-report.json`
- `outputs/plan-check.json`

## 交接/Next

执行阶段严格遵循 plan，所有源码改动完成后先跑全量 Rust 测试，再进入 single-active 部署。
