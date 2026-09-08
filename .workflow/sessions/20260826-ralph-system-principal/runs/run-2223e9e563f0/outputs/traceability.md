---
kind: traceability
schema: traceability/1.0
role: evidence
---

# System principal traceability

| Requirement | Layer | Evidence |
|---|---|---|
| No human login/session/admin path | L2 | `tests/service_principal_isolation.rs` |
| Atomic principal and audit mutation | L0/L1 | `tests/service_principal_store.rs` |
| No credential schema/surface | L1 | PostgreSQL `to_regclass` negative assertion |
| Zero production authorization | L3 | Verdict authoritative row counts |
| Single-active deployment | L3 | Docker runtime count and health |
