# Traceability

| Requirement | Scenario | Evidence |
|---|---|---|
| 独立于 human user | L2 login/SSO/admin isolation | `tests/service_principal_isolation.rs` |
| 创建时零 credential | L1 schema absence | isolated PostgreSQL 18 test |
| 生命周期与审计原子 | L0/L1 rollback | `tests/service_principal_store.rs` |
| 默认零授权 | L3 authority state | production Verdict counts = 0 |
| single-active 上线 | L3 deployment | one healthy Keystone instance |
