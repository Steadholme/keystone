---
verdict: ready
summary: "Identity-only system principal implemented, reviewed, pushed, deployed, and created in production."
constraints:
  - "The bootstrap principal has no credential, no grant, and no human login surface."
  - "Credential issuance/introspection remains forbidden until pending-deliver-active is implemented."
decisions:
  - "Security review narrowed the release from credential-capable to principal-only."
concerns: []
next:
  - "Design per-application principals and two-phase credential delivery during Rikune integration."
details:
  commit: "3f9a305a9e5a183568573dea2b24f6eb0d6b968a"
  image: "steadholme/keystone:3f9a305a9e5a-system-principal"
---
## 摘要

Keystone 已加入独立于 `users` 的 system principal，并完成生产创建。首个实例只有身份锚点，
没有 credential schema、签发 API、introspection route 或 Verdict grant。

## 结论/Verdict

ready。全量 Rust、隔离 PostgreSQL 18、双独立终审和生产健康检查全部通过。

## 讨论/复盘

原计划包含 credential 文件交付和 introspection。安全复核发现“数据库先激活、文件后写入”存在
进程崩溃窗口，路径交付还需要 dirfd 级防 TOCTOU。按用户要求避免在当前阶段钻牛角尖，本次
主动收缩为 principal-only；未来必须完成 `pending -> secure deliver -> active` 后才能恢复该 surface。

## 产物

- Source commit：`3f9a305a9e5a183568573dea2b24f6eb0d6b968a`
- Production image：`steadholme/keystone:3f9a305a9e5a-system-principal`
- Checkpoint：`/root/w33d_infra/backups/keystone-system-principal-20260826T131226Z`

## 交接/Next

Rikune 集成阶段再设计 per-app principal、两阶段 credential 交付、轮换和可追溯 introspection。
