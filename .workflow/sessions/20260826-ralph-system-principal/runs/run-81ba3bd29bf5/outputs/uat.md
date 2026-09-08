---
kind: uat-log
schema: uat-log/1.0
role: attachment
---

# Production UAT

1. Runtime：单个 Keystone candidate，healthy，restart 0。
2. Identity authority：principal = 1，Created event = 1，human user = 0，credential schema 不存在。
3. Authorization authority：Verdict tuple / policy edge / lifecycle row 均为 0。
4. Public SSO：health 返回 `ok`，OIDC issuer 保持 `https://sso.w33d.xyz`。
5. Provenance：Loom 与 GitHub `main` 均指向生产 source commit。

结果：5/5 passed。
