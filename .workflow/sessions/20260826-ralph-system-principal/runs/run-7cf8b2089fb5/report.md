---
verdict: ready
summary: "采用独立 service principal；本轮实现 lifecycle 与内部校验，但首个实例保持零授权且无 credential。"
constraints:
  - "不得进入 users 或任何 human login surface"
  - "不得参与人工审批或绕过现有 permission gate"
  - "credential 明文不得进入仓库、argv、日志或普通 receipt"
decisions:
  - "独立 service_principals/service_principal_tokens/durable events"
  - "operator-only CLI；internal introspection 使用 mTLS + consumer auth"
  - "首个 system principal 无 credential、无 scope、无 Verdict grant"
concerns:
  - "Verdict 的 service lifecycle fence 留到 Rikune 接入前补齐"
next:
  - "plan"
details:
  scope_verdict: medium
---

## 摘要

现有 `users` 和 OAuth client 都不能满足“结构性不可登录”的要求。实现应落在 Keystone 的独立非人身份模型，并复用 PAT 已验证的 opaque credential 生命周期。

## 结论/Verdict

可以进入计划阶段。当前边界是 Keystone 源码、测试与部署；Strad、Verdict grant、Access Governance 审批逻辑和每应用 principal 均不在本轮扩张。

## 讨论/复盘

用户已明确：先创建一个 system 账户，每个应用的独立账户等 Rikune 集成后再做。基于这一反馈，首个实例不提前签发无人消费的 secret。

## 产物

- `outputs/findings.json`
- `outputs/risk-matrix.json`

## 交接/Next

计划需要覆盖 additive schema、双 Store 实现、operator CLI、mTLS/consumer-auth introspection、负向测试、single-active 部署，以及首个零授权 principal 的创建与验证。
