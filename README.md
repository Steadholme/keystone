# Keystone

Keystone 是一个用 Rust（axum 0.8）实现的、符合标准的 **OIDC / OAuth2 授权服务器（Authorization Server）**。
核心切片：`authorization_code` + **PKCE（S256，强制）** 流程，端到端可用，
签发可通过自身 JWKS 验证的 **RS256** access token 与 id token。

在此之上接入了**真实的登录系统**（取代早期的自动批准）：服务端会话（server-side session）+
**Passkey（WebAuthn）** 登录，并带**密码兜底（Argon2id）**。`/authorize` 现在**强制校验会话**：无会话 →
302 跳转 `/login?return_to=<原始 /authorize URL>`；有会话 → 为已认证用户签发授权码并回跳 `redirect_uri`。
登录 UI 为服务端渲染（无独立前端 / 容器），JS/CSS 经 `include_str!` 嵌入二进制。

## 它是什么

- 默认开发监听：`127.0.0.1:8080`，issuer = `http://127.0.0.1:8080`（均可由环境变量覆盖，见下）
- 公开客户端（public client，无 client secret），安全性依赖 **redirect_uri 精确匹配** + **单次使用、PKCE 绑定的授权码**
- 一对 RSA-2048 密钥常驻 `Arc<SigningKey>`；`kid` 采用 RFC 7638 JWK thumbprint，
  保证 JWKS 中的 `kid` 与 JWT header 中的 `kid` 永不漂移
- **签名密钥可持久化**：设置 `SIGNING_KEY_PATH` 后，密钥从该 PEM 文件加载（不存在则生成并写入），
  因此 `kid` 在**重启后保持稳定**——避免重启 Keystone 轮换 `kid`、导致 Sluice 在刷新窗口内拒签（401）的问题；
  未设置时每次启动生成临时密钥（dev/test 默认，行为不变）

## 如何运行

```bash
# 构建
cargo build

# 运行（监听 127.0.0.1:8080）
cargo run

# 测试（默认内存存储，无需数据库 —— 契约/登录/机密客户端/mTLS 配置单测全绿）
cargo test
```

冒烟验证（服务运行后）：

```bash
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/.well-known/openid-configuration | jq .
curl -s http://127.0.0.1:8080/jwks.json | jq .
```

## 配置（环境变量）

所有 dev 契约中硬编码的值现已可由环境变量覆盖；**环境变量未设置时保持原有默认值**，因此默认行为与之前完全一致。

| 变量 | 作用 | 默认值 |
|------|------|--------|
| `BIND_ADDR` | 监听地址（容器内通常设 `0.0.0.0:8080`） | `127.0.0.1:8080` |
| `ISSUER` | JWT `iss` 与发现文档中的 issuer；所有端点 URL 由它派生 | `http://127.0.0.1:8080` |
| `KEYSTONE_STORE` | 存储后端：`memory` \| `postgres` | `memory` |
| `DATABASE_URL` | Postgres DSN（仅 `postgres` 模式需要） | 无 |
| `SIGNING_KEY_PATH` | RSA 签名密钥的 PEM 文件路径（PKCS#1）。设置后从该文件**加载或生成并持久化**密钥，使 `kid` 跨重启稳定；不存在则首启生成、文件权限 `0600`、自动创建父目录。**未设置**则每次启动生成临时密钥（dev/test 默认） | 无（临时密钥） |
| `WEBAUTHN_RP_ID` | WebAuthn relying-party id。用**父域** `w33d.xyz`，使 passkey 可跨未来 `*.w33d.xyz` 子服务复用 | `w33d.xyz` |
| `WEBAUTHN_RP_ORIGIN` | WebAuthn relying-party origin（单一公网入口） | `https://id.w33d.xyz` |
| `SESSION_SECRET` | `__Host-session` cookie 的 HMAC-SHA256 签名密钥；**生产必须覆盖** | dev 默认串（须替换） |
| `BOOTSTRAP_ADMIN_PASSWORD` | 启动时一次性为种子管理员（`u_admin`）设置 Argon2 密码哈希（仅当其尚无哈希时）。**永不写日志**；幂等（已有哈希则忽略） | 无（不设密码） |
| `GW_CLIENT_ID` | 机密网关客户端 id（Sluice 作为带 secret 的 OIDC RP） | `sluice-gw` |
| `GW_CLIENT_SECRET` | 机密网关客户端密钥。**设置时**才会播种该客户端（Argon2id 哈希入库，幂等 UPSERT），并启用仅供该网关调用的 PAT introspection；不设置时 introspection fail closed 为 `503` | 无 |
| `GW_REDIRECT_URI` | 网关客户端回调地址 | `https://id.w33d.xyz/_gw/auth/callback` |
| `KEYSTONE_REGISTRATION_MAC_KID` | registration feed 当前 HMAC key id；`[A-Za-z0-9._-]`，最长 64 bytes。feed 上线时必填 | 无 |
| `KEYSTONE_REGISTRATION_MAC_KEY` | registration feed 当前 HMAC-SHA256 secret；32–512 visible ASCII bytes。feed 上线时必填 | 无 |
| `KEYSTONE_REGISTRATION_MAC_KID_PREV` | 滚动轮换期间可验签的上一 KID；必须与上一 key 成对配置，且不得等于当前 KID | 无 |
| `KEYSTONE_REGISTRATION_MAC_KEY_PREV` | 滚动轮换期间可验签的上一 HMAC secret；必须与上一 KID 成对配置 | 无 |
| `INTERNAL_TLS` | 内部 mTLS 开关，`on` 启用（其余/未设 = 关闭，行为不变） | 关闭 |
| `INTERNAL_TLS_ADDR` | mTLS 监听地址（`INTERNAL_TLS=on` 时） | `0.0.0.0:8443` |
| `INTERNAL_TLS_CERT` | 服务端证书 PEM 路径（Keyward 签发，CN/SAN=`keystone`） | 无（开 mTLS 时必填） |
| `INTERNAL_TLS_KEY` | 服务端私钥 PEM 路径 | 无（开 mTLS 时必填） |
| `INTERNAL_TLS_CLIENT_CA` | 客户端 CA PEM 路径（Keyward `root.crt`），用于校验 Sluice 的客户端证书 | 无（开 mTLS 时必填） |
| `INTERNAL_HEALTH_ADDR` | 明文回环健康监听地址（供 docker healthcheck，无需客户端证书） | `127.0.0.1:8081` |
| `AUDIT_ENABLED` | 审计事件发射开关，`on`/`true`/`1`/`yes` 启用（其余/未设 = 关闭，行为不变） | 关闭 |
| `WATCHTOWER_URL` | Watchtower 审计入库基址（内部明文）；发射器在其后追加 `/events` | `http://watchtower:8500` |
| `AUDIT_INGEST_TOKEN` | Watchtower 入库 bearer token（`Authorization: Bearer …`）。**永不写日志、永不入字段**；未设置则即便 `AUDIT_ENABLED=on` 也保持关闭 | 无 |

> 在 docker-compose 中，规范 issuer 为网络内服务名 `http://keystone:8080`：将 `ISSUER=http://keystone:8080`、`BIND_ADDR=0.0.0.0:8080` 即可让 Keystone 把该值嵌入 JWT 并在发现文档中对外广播，Sluice 据此拉取 discovery / JWKS 并校验 `iss`。

## PostgreSQL 存储模式

设 `KEYSTONE_STORE=postgres` 后，启动时会：连接 `DATABASE_URL` → 运行**幂等**建表迁移（`CREATE TABLE IF NOT EXISTS`）→ 以 **UPSERT** 幂等播种 dev client + user → 将 `Arc<dyn Store>` 接到 PG 实现。内存实现（`memory`）仍是默认，现有测试套件无需数据库即可全绿。

- **驱动**：`sqlx`（`PgPool`），仅用**运行时查询**（`sqlx::query` / `Row`），不使用 `query!` 编译期宏 —— 因此**构建无需数据库**；TLS 走 `rustls`（无 native-tls / openssl）。
- **可移植 SQL**（为日后无改动迁移到 FusionDB over pgwire）：仅用 `TEXT/BIGINT/...` 标准类型、`PRIMARY KEY/UNIQUE/NOT NULL` 约束、参数化查询、`INSERT ... ON CONFLICT` UPSERT。**不用** JSONB / 数组 / SERIAL / 扩展 / 存储过程。
- **表结构**：`oauth_clients(client_id PK, name)`、`client_redirect_uris(client_id, redirect_uri)`（**子表**，而非数组列）、`users(sub PK, email UNIQUE)`、`auth_codes(code PK, client_id, redirect_uri, code_challenge, sub, nonce, scope, expires_at BIGINT)`。授权码**单次使用 = 消费即删除**。

运行（连接外部 Postgres）：

```bash
KEYSTONE_STORE=postgres \
DATABASE_URL=postgres://postgres:pw@127.0.0.1:5432/keystone \
ISSUER=http://127.0.0.1:8080 BIND_ADDR=0.0.0.0:8080 \
cargo run
```

Postgres 集成测试（仅在设置 `TEST_DATABASE_URL` 时运行，否则打印说明并直接跳过，不影响默认无库测试）：

```bash
# 起一个一次性 Postgres
docker run -d --rm --name ks-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=keystone \
  -p 127.0.0.1:55432:5432 postgres:18-alpine
# 跑集成测试
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55432/keystone \
  cargo test --test pg_store -- --nocapture
docker rm -f ks-testpg
```

## Docker

```bash
# 构建镜像
docker build -t steadholme/keystone:dev .

# 运行（内存存储）
docker run --rm -p 8080:8080 -e KEYSTONE_STORE=memory steadholme/keystone:dev

# 运行（Postgres 存储）
docker run --rm -p 8080:8080 \
  -e KEYSTONE_STORE=postgres \
  -e DATABASE_URL=postgres://postgres:pw@db:5432/keystone \
  -e ISSUER=http://keystone:8080 \
  steadholme/keystone:dev

# 运行（持久化签名密钥 —— kid 跨重启稳定）
# 镜像内置 /data 目录并 chown 给非 root uid 10001；挂一个具名卷到 /data 即可读写。
docker run --rm -p 8080:8080 \
  -e KEYSTONE_STORE=memory \
  -e SIGNING_KEY_PATH=/data/signing_key.pem \
  -v keystone_keys:/data \
  steadholme/keystone:dev
```

> 镜像以非 root（uid `10001`）运行，且内置 `mkdir -p /data && chown 10001:10001 /data`，
> 因此挂载的具名卷会继承可写属主。密钥**不**烘焙进镜像，仅在运行时于 `SIGNING_KEY_PATH` 生成 / 持久化（权限 `0600`）。
> 在 docker-compose 中：给 keystone 服务设 `SIGNING_KEY_PATH: /data/signing_key.pem` 并挂一个具名卷 `keystone_keys:/data`。

镜像为多阶段构建（`rust:1.96-slim` 构建 → `debian:trixie-slim` 运行），**非 root** 用户、仅 rustls（无 openssl）、`EXPOSE 8080`。容器 `HEALTHCHECK` 使用内置子命令 `keystone healthcheck`（裸 TCP 请求 `/healthz`，无需 curl）。

## v0 覆盖的端点

| Method | Path | 说明 |
|--------|------|------|
| GET | `/healthz` | 存活探针，返回 `200 "ok"` |
| GET | `/.well-known/openid-configuration` | OIDC 发现文档 |
| GET | `/jwks.json` | JWKS，恰好一个 RS256 公钥 |
| GET | `/authorize` | `authorization_code` + PKCE(S256)；**校验会话**：无会话 302 跳 `/login`，有会话签码并回跳 |
| POST | `/token` | 消费单次授权码，校验 PKCE 与绑定，返回 access/id token |
| GET | `/userinfo` | `Authorization: Bearer <access_token>`，返回 `{sub, email}` |
| POST | `/internal/v1/pats/introspect` | 内部 PAT introspection；HTTP Basic 网关认证 + form `token`，返回权威 active 状态 |
| POST | `/internal/v1/identity/registration/snapshot` | Access registration consumer 创建不可变 materialized snapshot；仅 mTLS + RegSig |
| GET | `/internal/v1/identity/registration/snapshot/{snapshot_id}` | 按 immutable ordinal 分页读取同一 snapshot |
| GET | `/internal/v1/identity/registration/changes` | 从严格连续 cursor 拉 full-state registration events |
| POST | `/internal/v1/identity/registration/ack` | 持久化 generation-fenced、event/hash-bound 单调 ACK |
| GET·POST | `/login` | 服务端渲染登录页（passkey 按钮 + 用户名/密码表单）；POST 校验 CSRF + Argon2 后建会话 |
| GET | `/account` | 需会话：显示当前用户 + “注册 passkey” + 登出 |
| POST | `/logout` | 校验 CSRF，销毁会话并清 cookie |
| GET | `/static/{file}` | 嵌入式 `app.css` / `login.js`（`include_str!`，slim 镜像零缺文件） |
| POST | `/webauthn/register/begin` · `/finish` | 需会话：开始/完成 passkey 注册，持久化 `Passkey` |
| POST | `/webauthn/authenticate/begin` · `/finish` | 按用户名开始/完成 passkey 认证（无需密码），成功后建会话 |

### 登录与会话设计

- **会话**：服务端存储（`sessions` 表，可移植 SQL），`__Host-session` cookie 携带不透明 session id 并用
  `SESSION_SECRET` 做 **HMAC-SHA256 签名**（被篡改的 cookie 在查库前即被拒）。cookie 属性：`Secure; HttpOnly; SameSite=Lax; Path=/`。
- **密码兜底**：`users.password_hash`（可空）存 **Argon2id** PHC 串；`POST /login` 用 `username`（匹配 `sub` 或 `email`）查用户并常数时间校验。
- **Passkey（WebAuthn）**：`webauthn-rs 0.5`，rp_id=`w33d.xyz`、rp_origin=`https://id.w33d.xyz`；in-flight ceremony state 存 `webauthn_states` 表，以短时 `__Host-wa` cookie 关联；每次认证按需 `update_credential` 递增计数器。
- **CSRF**：所有 POST 采用 **double-submit**（`__Host-csrf` cookie ↔ 表单 `csrf_token` 字段 / fetch 的 `X-CSRF-Token` 头），常数时间比对。

种子数据（seed）：

- Client（公开）：`{ client_id: "sluice-dev", redirect_uris: ["http://127.0.0.1:9090/callback", "https://id.w33d.xyz/callback"] }`
- Client（机密，仅当设置 `GW_CLIENT_SECRET` 时）：`{ client_id: "sluice-gw", redirect_uris: ["https://id.w33d.xyz/_gw/auth/callback"], client_secret_hash: Argon2id(...) }`
- User：`{ sub: "u_admin", email: "admin@steadholme.local" }`

## 机密客户端（confidential clients）

客户端分两类，由 `oauth_clients.client_secret_hash`（可空 TEXT，Argon2id PHC 串）区分：

- **公开客户端（public）**：`client_secret_hash` 为 `NULL`，仅靠 **PKCE（S256）** 保护，`/token` 不需要密钥（如 `sluice-dev`）。**行为与此前完全一致。**
- **机密客户端（confidential）**：`client_secret_hash` 非空，`/token` **必须**校验客户端所示密钥（**常数时间** Argon2id 比对），支持两种认证方式：
  - `client_secret_post`：在表单里带 `client_id` + `client_secret`；
  - `client_secret_basic`：`Authorization: Basic base64(client_id:client_secret)`。
  - 两处都带 `client_id` 时**必须一致**；错误/缺失密钥 → **401 `invalid_client`**（`WWW-Authenticate: Basic`）。
  - 客户端认证在**消费授权码之前**完成：认证失败**不会**烧毁单次授权码。
  - PKCE 对所有客户端仍强制（机密客户端 = 机密 + PKCE 双重）。

发现文档据此广播：`token_endpoint_auth_methods_supported = ["client_secret_post", "client_secret_basic", "none"]`。

机密网关客户端（Sluice 作为带 secret 的 OIDC RP）从环境变量**幂等播种**：设置 `GW_CLIENT_SECRET` 后，于启动时把密钥 Argon2id 哈希并 UPSERT（`GW_CLIENT_ID` 默认 `sluice-gw`、`GW_REDIRECT_URI` 默认 `https://id.w33d.xyz/_gw/auth/callback`，scope = openid/email/profile）。`id_token` 的 `aud` = 请求方 `client_id`、`nonce`（若 `/authorize` 带上）原样回传，供 RP 校验。

> 提示：HTTP Basic 中 `client_id:secret` 按 base64 编码；为避免 RFC 6749 §2.3.1 的表单编码歧义，`GW_CLIENT_SECRET` 建议使用 **URL-safe**（不含 `:` / `/` / `+` 等）的强随机串。

### PAT introspection（内部服务契约）

`POST /internal/v1/pats/introspect` 供 Sluice 使用同一组 `GW_CLIENT_ID` / `GW_CLIENT_SECRET`
查询 opaque PAT 的权威状态。生产应只经 Keystone 的内部 mTLS listener 调用；PAT 明文只允许出现在
`application/x-www-form-urlencoded` body 中，禁止放入 URL、query 或日志。

```text
Authorization: Basic base64(GW_CLIENT_ID:GW_CLIENT_SECRET)
Content-Type: application/x-www-form-urlencoded

token=pat_<base64url-no-pad>
```

- token 总长度上限为 `128` bytes；前缀必须精确为小写 `pat_`，payload 仅允许
  `[A-Za-z0-9_-]+`。当前签发格式固定为 `pat_` + 43 字符 payload（总长 47）。
- active 响应：`200 {"active":true,"sub":"…","scope":"…","exp":…,"token_type":"Bearer"}`。
  `scope` 是空格分隔字符串，调用方必须做完整 token membership，不得做子串匹配。
- 无效、未知、已撤销、已过期，或 owner 已 disabled / 不存在时统一返回
  `200 {"active":false}`，不泄漏失效原因。
- Basic 缺失或错误返回 `401 invalid_client`；`GW_CLIENT_SECRET` 未配置或 Store/数据库故障返回
  `503 temporarily_unavailable`，不得降级为 inactive 或使用 stale authority。
- 所有响应（包括 body-limit / extractor 的 `4xx`）均带
  `Cache-Control: private, no-store` 与 `Vary: Authorization`。
- Keystone 只持久化 PAT 的 SHA-256 hash；introspection 按 hash 查询，并同时强制
  `revoked_at = 0`、`expires_at > now`、`users.disabled = false`。响应和日志均不包含 token/hash。

## 内部 mTLS（keystone↔sluice，env 开关，默认关闭）

为内部 keystone↔sluice 这一跳提供**双向 TLS**。**默认关闭**——不设 `INTERNAL_TLS` 时行为与此前完全一致（明文 `:8080`），失败可安全降级。

`INTERNAL_TLS=on` 时：

- 在 `INTERNAL_TLS_ADDR`（默认 `0.0.0.0:8443`）启用 **HTTPS** 监听，加载 **Keyward 签发**的服务端证书/私钥（`INTERNAL_TLS_CERT` / `INTERNAL_TLS_KEY`，CN/SAN=`keystone`），并**强制校验客户端证书**——校验其链到 `INTERNAL_TLS_CLIENT_CA`（Keyward `root.crt`），即 mutual TLS。同一 axum app 经此 mTLS 端口提供服务。
- 另起一个**绑定 `127.0.0.1` 的明文健康监听**（`INTERNAL_HEALTH_ADDR`，默认 `127.0.0.1:8081`）供 docker `HEALTHCHECK`，**无需**客户端证书；内置 `keystone healthcheck` 子命令会根据 `INTERNAL_TLS` 自动探测该端口。
- **不**绑定公共明文 `BIND_ADDR`；Sluice 仅经 mTLS `:8443` 访问 keystone。证书/路径缺失则进程 `exit 1` **显式失败**（不静默降级）。

实现：`rustls` 固定 **`ring`** crypto provider（显式传入 builder，匹配 sqlx 已编译的 provider，**不引入 aws-lc-rs**、不依赖进程级默认 provider），`rustls-pemfile` 加载 PEM，`tokio-rustls` + `hyper`(http1) 提供服务。

```bash
# 本地 mTLS 冒烟（自备 CA + CN=keystone 服务端证书 + 客户端证书）
docker run --rm -e KEYSTONE_STORE=memory -e INTERNAL_TLS=on \
  -e INTERNAL_TLS_CERT=/tls/server.crt -e INTERNAL_TLS_KEY=/tls/server.key \
  -e INTERNAL_TLS_CLIENT_CA=/tls/ca.crt \
  -v "$PWD/tls":/tls:ro -p 127.0.0.1:8443:8443 steadholme/keystone:dev
# 带客户端证书 -> 200 ok；不带 -> TLS 握手被拒（certificate required）
curl --cacert tls/ca.crt --cert tls/client.crt --key tls/client.key \
  --resolve keystone:8443:127.0.0.1 https://keystone:8443/healthz
```

## Access registration authority feed（`regfeed-v1`）

该 feed 是 Keystone → Access Governance 的 identity registration authority，不是新的公网 API。
生产启用必须同时满足：`KEYSTONE_STORE=postgres`、`INTERNAL_TLS=on`、当前 RegSig KID/key
已配置，以及 Access 使用受 `INTERNAL_TLS_CLIENT_CA` 信任的客户端证书直连 mTLS listener。
明文 `INTERNAL_HEALTH_ADDR` 只挂 `/healthz`，访问任意 `/internal` 路径均为 `404`；公网
Sluice 也不得发布 `/internal`。缺少 mTLS 模式或 RegSig 配置时 feed fail closed 为 `503`。

固定 consumer 是 `access-governance-registration-v1`，固定 service identity 是
`access-governance`，固定 audience 是 `keystone-registration`；三者都是 compile-time protocol
constant，不提供 env override。当前 source
`generation` 存在 `identity_outbox_clock`，初始为 `1`；snapshot／changes 返回该 generation，
Access 必须原样带回 ACK。恢复 authority 或 fenced cutover 时只能单调提升该 generation，旧
generation ACK 返回 `409 ack_generation_conflict`。

### Endpoints 与 DTO

```text
POST /internal/v1/identity/registration/snapshot
body: empty
201 {snapshot_id,generation,high_watermark,count,digest,acked_nonce}

GET /internal/v1/identity/registration/snapshot/{snapshot_id}?after_ordinal=<u64>&limit=<1..1000>
200 {snapshot_id,generation,high_watermark,digest,rows[],next_after_ordinal,done,acked_nonce}
row  {ordinal,subject,account_version,registration_state,email_verified,enabled,payload_hash}

GET /internal/v1/identity/registration/changes?after=<u64>&limit=<1..500>
200 {generation,events[],head_cursor,retention_floor_cursor,acked_nonce}
event {cursor,event_id,subject,account_version,registration_state,email_verified,enabled,
       payload_hash,occurred_at}

POST /internal/v1/identity/registration/ack
body: {consumer,generation,cursor,event_id,payload_hash}
200  {consumer,generation,stored_cursor,acked_nonce}
```

ACK JSON 使用 strict `deny_unknown_fields`；wire 字段是 `cursor`，不是旧草案的
`acked_cursor`。所有通过 MAC/replay authentication 的响应，包括 `409`、`410`、`503`，
都回显原请求 32-char lowerhex nonce 为 `acked_nonce`。响应统一带
`Cache-Control: private, no-store` 与 `Vary: X-Keystone-RegSig`。

冻结错误码：`400 malformed_sig|invalid_request`；
`401 unknown_kid|stale|bad_mac|replay`；
`409 snapshot_incomplete|ack_regression|ack_generation_conflict|ack_ahead|ack_event_mismatch`；
`410 resnapshot_required`；
`503 feed_gap|registration_feed_unavailable`。

状态是 full-state snapshot：`registered | unverified | disabled | deleted`。`subject` 固定为
`user:<raw Keystone sub>`。Access lifecycle 写回造成的 `disabled_by_lifecycle=true` 会从
registration authority 投影中掩掉，因此不会形成自反馈；manual identity disable 仍正常输出
`disabled`。create／verify／unverify／manual enable-disable／delete 在同一 PostgreSQL TX 中完成
user/tombstone mutation、`account_version`、transactional cursor clock 与 outbox insert，任一失败
整体回滚。

### RegSig canonical bytes

Header：`X-Keystone-RegSig: kid=<kid>,ts=<unix-seconds>,nonce=<32-lowerhex>,mac=<64-lowerhex>`。
timestamp 允许的固定 skew 为 ±60s；nonce 在 PostgreSQL replay 表中原子 claim。当前 + previous
KID 可验签，只有 current 用于新请求。canonical 字段以单个 `\n` 分隔，末尾无 LF：

```text
regfeed-v1
access-governance
keystone-registration
<METHOD>
<exact_path>
<raw_query_fields_sorted_by_bytes>
<lowerhex_sha256(raw_body)>
<kid>
<unix_seconds>
<nonce>
```

snapshot POST 的 body hash 必须是 SHA256(empty)。snapshot digest v1 为
`registration-snapshot-v1\n{high_watermark}`，随后按 1-based ordinal 为每行追加（前置 LF、
最终无尾 LF）：

```text
\nR\t{ordinal}\t{subject}\t{account_version}\t{registration_state}\t{email_verified 0|1}\t{enabled 0|1}\t{payload_hash}
```

payload hash 为 lowerhex SHA256，canonical 是
`registration-payload-v1\n{subject}\n{account_version}\n{registration_state}\n{email_verified 0|1}\n{enabled 0|1}`，
末尾无 LF。

### Migration 与 retention

`PgStore::migrate` 以 additive、幂等 DDL 增加 `users.account_version`、
`identity_outbox_clock`、`identity_registration_outbox`、retained tombstone、immutable snapshot
manifest/rows、consumer ACK 与 durable replay 表。snapshot 在一个 `SERIALIZABLE` TX 中物化；
sealed manifest/rows 由 PostgreSQL trigger 拒绝 UPDATE/DELETE。cursor 通过同 TX singleton clock
分配，rollback 不消耗 cursor。

ACK 后只会裁掉「所有已知 consumer 均已 ACK」且「连续前缀事件已超过 30 天」的 outbox；
tombstone 永不物删。落后到 `after < retention_floor_cursor` 返回
`410 {"error":"resnapshot_required","acked_nonce":"…"}`，Access 必须清除 snapshot readiness 并
重新 materialize，不得以空页假追平。

## 审计事件发射（keystone → Watchtower，env 开关，默认关闭）

把安全相关动作以**非阻塞、即发即弃（fire-and-forget）**的方式发射到 Watchtower 的不可篡改哈希链审计脊柱。**默认关闭**——不设 `AUDIT_ENABLED` 时为**空操作（no-op）**：不建通道、不起 worker、行为与此前完全一致。

**绝对约束：** 发射审计事件**绝不**阻塞、拖慢或失败认证请求路径。`AuditSink`（位于 `AppState`）持有一个**有界** `tokio::mpsc` 通道（容量 `1024`）；处理器用 `try_send` 入队后立即返回——队列满或 worker 已退出则**丢弃**该事件（warn + 丢弃计数器），**绝不**把错误传播给用户请求。一个后台 worker 排空通道，对每个事件向 `WATCHTOWER_URL/events` 发起带 `Authorization: Bearer AUDIT_INGEST_TOKEN` 的 POST，单次预算 **2s** 超时。**Watchtower 宕机不会影响登录或令牌签发。** 目标是内部明文 `http://watchtower:8500`，故采用**手写 HTTP/1.1**（`tokio` 裸 TCP，复刻 `main` 中依赖最小的 healthcheck 探针），**不引入** TLS 客户端 / openssl。

**无机密泄露：** 事件只携带共享逻辑字段 `actor` / `action` / `target` / `severity` / `detail` / `source`（`source` 恒为 `keystone`，seq/ts/hash 由 Watchtower 赋予）。**绝不**写入口令、token、client secret、完整 cookie、`code_verifier` 或签名材料；`login.failure` 只记录**提交的用户名 + 固定原因**（`"invalid credentials"`，**永不**含口令）。唯一上线的凭据是 `Authorization` 头里的 bearer token（不作为字段）。

已埋点的事件（`source="keystone"`）：

| action | actor | target | severity | 触发点 |
|--------|-------|--------|----------|--------|
| `login.success` | 用户 email | `password` | info | 口令登录成功（`POST /login`） |
| `login.failure` | 提交的用户名 | `password` | warning | 口令校验失败（`detail="invalid credentials"`） |
| `webauthn.authenticate.success` | 用户 email | 凭据 id | info | passkey 登录成功 |
| `webauthn.authenticate.failure` | `anonymous` | `passkey` | warning | passkey 断言校验失败 |
| `webauthn.register` | 用户 email | 凭据 id（公开） | info | passkey 注册完成 |
| `token.issue` | 用户 sub | client_id | info | `/token` 成功签发 |
| `authorize.grant` | 用户 sub | client_id | info | `/authorize` 为会话签发授权码 |
| `client_auth.failure` | client_id | `token_endpoint` | warning | 机密客户端 secret 错误/缺失 |
| `session.logout` | 用户 email | `session` | info | `POST /logout` |

> 开启方式（compose）：在 keystone 服务环境中设 `AUDIT_ENABLED=on`、`WATCHTOWER_URL=http://watchtower:8500`、`AUDIT_INGEST_TOKEN=${AUDIT_INGEST_TOKEN}`（与 `deploy/.env` 中同名值一致）。关闭时零行为变化，现有测试全绿。

## 关键设计

- **加密路径是脊梁**：`jsonwebtoken 10`（`default-features=false` + `rust_crypto`，纯 Rust，无 C 工具链），
  `rsa 0.9` 生成密钥，`EncodingKey::from_rsa_der`（PKCS#1 DER）签名，
  `DecodingKey::from_rsa_components(n, e)` 验签——这正是 Sluice 从 JWKS 验签所走的同一路径，
  因此集成测试本身就证明了两服务的互操作。
- **存储是可插拔的 `async Store` trait**（`async-trait`）：方法 `get_client / get_user / put_code / take_code`（原子单次消费），handler 不接触任何具体存储类型，直接在服务运行时上 `.await` 存储方法。
  现有两套实现：默认 `InMemoryStore`（`Mutex<HashMap>`，临界区全同步、锁守卫不跨 `.await`）与可移植的 `PgStore`（sqlx + Postgres）；后者原生 `.await` sqlx，不再用 `block_in_place`/`Handle::block_on` 同步桥接，因此 DB 往返永不阻塞 worker 线程。
- **PKCE S256 强制**：`/authorize` 缺少 `code_challenge` 或 `code_challenge_method != S256` 一律 400；
  `/token` 重算 `base64url(sha256(verifier))` 与存储的 challenge 比对。无 plaintext PKCE，无 implicit/hybrid。
- 授权码为 32 字节 CSPRNG 不透明值，单次使用，60s TTL，绑定 `client_id + redirect_uri + code_challenge + sub + nonce + scope`。

## 已延后（deferred / TODO seam）

- **FusionDB 后端存储**：现已提供**可移植的 PostgreSQL 数据层**（`PgStore`，仅标准 SQL），日后可无改动迁移到 FusionDB over pgwire；但 FusionDB 本身**尚未接入**，默认仍为 `InMemoryStore`。
- **密钥持久化**：已实现——设置 `SIGNING_KEY_PATH` 即把签名密钥持久化到 PEM 文件，`kid` 跨重启稳定（见上）。未设置时仍为临时密钥。
- **密钥轮换 / HSM**：仍延后；`keys.rs` 标注了从 FusionDB/HSM 加载并轮换的 TODO 接缝。
- **登录 / Passkey / 密码兜底**：**已实现**——`/authorize` 现强制校验会话；passkey（WebAuthn）注册/认证 + Argon2 密码兜底；登录 UI 服务端渲染、JS/CSS 嵌入二进制。
- **同意（consent）**：v0 对第一方种子客户端 `sluice-dev` 采用**自动同意**（已认证用户即放行）；多客户端的细粒度同意页延后。
- **MFA / refresh token / social login / 密钥轮换 / HSM**：仍延后。
- **TLS**：对外 TLS 由 Sluice/ACME 在 `https://id.w33d.xyz` 前面终结。内部 keystone↔sluice 这一跳现支持**可选的双向 TLS（mTLS）**（`INTERNAL_TLS=on`，见上「内部 mTLS」）；**默认关闭**，关闭时仍为明文 `:8080`。

## 浏览器 passkey 手动验证（manual test recipe）

无浏览器的 passkey 证明已由 `tests/webauthn_flow.rs`（`SoftPasskey` 软件认证器）端到端覆盖；下面是**真人浏览器**流程：

1. 部署后访问 `https://id.w33d.xyz/login`（需有效 TLS——`__Host-` cookie 与 WebAuthn 都要求 HTTPS）。
2. 用 `BOOTSTRAP_ADMIN_PASSWORD` 设定的密码，以用户名 `admin@steadholme.local`（或 `u_admin`）走**密码兜底**登录 → 跳转 `/account`。
3. 在 `/account` 点击 **“Register a passkey”**，按浏览器/系统提示用平台认证器（Touch ID / Windows Hello / 手机）完成注册；页面显示注册成功后 passkey 计数变为 1。
4. 登出（`/logout`），回到 `/login`，在下半部输入用户名后点 **“Sign in with a passkey”** → 完成 WebAuthn 断言即**无密码登录**，跳回 `/account`。
5. 端到端 OIDC：让 Sluice 发起 `GET https://id.w33d.xyz/authorize?...`（PKCE S256）。未登录会先 302 到 `/login`；完成上面的登录后回到 `/authorize` 即 302 携 `code` 回跳 `https://id.w33d.xyz/callback`，再由 `/token`、`/userinfo` 完成。

> 说明：因引入 `webauthn-rs`（其 `webauthn-rs-core` 依赖 OpenSSL），构建镜像的 builder 阶段新增 `libssl-dev`/`pkg-config`，runtime 阶段新增 `libssl3`/`ca-certificates`（见 `Dockerfile`）。
