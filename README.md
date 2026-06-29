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

# 测试（默认内存存储，无需数据库 —— 17 个契约测试全绿）
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
docker build -t holdfast/keystone:dev .

# 运行（内存存储）
docker run --rm -p 8080:8080 -e KEYSTONE_STORE=memory holdfast/keystone:dev

# 运行（Postgres 存储）
docker run --rm -p 8080:8080 \
  -e KEYSTONE_STORE=postgres \
  -e DATABASE_URL=postgres://postgres:pw@db:5432/keystone \
  -e ISSUER=http://keystone:8080 \
  holdfast/keystone:dev

# 运行（持久化签名密钥 —— kid 跨重启稳定）
# 镜像内置 /data 目录并 chown 给非 root uid 10001；挂一个具名卷到 /data 即可读写。
docker run --rm -p 8080:8080 \
  -e KEYSTONE_STORE=memory \
  -e SIGNING_KEY_PATH=/data/signing_key.pem \
  -v keystone_keys:/data \
  holdfast/keystone:dev
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

- Client：`{ client_id: "sluice-dev", redirect_uris: ["http://127.0.0.1:9090/callback"] }`
- User：`{ sub: "u_admin", email: "admin@holdfast.local" }`

## 关键设计

- **加密路径是脊梁**：`jsonwebtoken 10`（`default-features=false` + `rust_crypto`，纯 Rust，无 C 工具链），
  `rsa 0.9` 生成密钥，`EncodingKey::from_rsa_der`（PKCS#1 DER）签名，
  `DecodingKey::from_rsa_components(n, e)` 验签——这正是 Sluice 从 JWKS 验签所走的同一路径，
  因此集成测试本身就证明了两服务的互操作。
- **存储是可插拔的 `Store` trait**：方法 `get_client / get_user / put_code / take_code`（原子单次消费），handler 不接触任何具体存储类型。
  现有两套实现：默认 `InMemoryStore`（`Mutex<HashMap>`）与可移植的 `PgStore`（sqlx + Postgres）；后者在同步 trait 方法内经 `block_in_place` 桥接到 async sqlx（生产 `#[tokio::main]` 与 `multi_thread` 集成测试均满足多线程运行时要求）。
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
- **TLS**：Keystone 绑定明文 HTTP；TLS 由 Sluice/ACME 在 `https://id.w33d.xyz` 前面终结。

## 浏览器 passkey 手动验证（manual test recipe）

无浏览器的 passkey 证明已由 `tests/webauthn_flow.rs`（`SoftPasskey` 软件认证器）端到端覆盖；下面是**真人浏览器**流程：

1. 部署后访问 `https://id.w33d.xyz/login`（需有效 TLS——`__Host-` cookie 与 WebAuthn 都要求 HTTPS）。
2. 用 `BOOTSTRAP_ADMIN_PASSWORD` 设定的密码，以用户名 `admin@holdfast.local`（或 `u_admin`）走**密码兜底**登录 → 跳转 `/account`。
3. 在 `/account` 点击 **“Register a passkey”**，按浏览器/系统提示用平台认证器（Touch ID / Windows Hello / 手机）完成注册；页面显示注册成功后 passkey 计数变为 1。
4. 登出（`/logout`），回到 `/login`，在下半部输入用户名后点 **“Sign in with a passkey”** → 完成 WebAuthn 断言即**无密码登录**，跳回 `/account`。
5. 端到端 OIDC：让 Sluice 发起 `GET https://id.w33d.xyz/authorize?...`（PKCE S256）。未登录会先 302 到 `/login`；完成上面的登录后回到 `/authorize` 即 302 携 `code` 回跳 `https://id.w33d.xyz/callback`，再由 `/token`、`/userinfo` 完成。

> 说明：因引入 `webauthn-rs`（其 `webauthn-rs-core` 依赖 OpenSSL），构建镜像的 builder 阶段新增 `libssl-dev`/`pkg-config`，runtime 阶段新增 `libssl3`/`ca-certificates`（见 `Dockerfile`）。
