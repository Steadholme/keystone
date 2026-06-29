# Keystone

Keystone 是一个用 Rust（axum 0.8）实现的、符合标准的 **OIDC / OAuth2 授权服务器（Authorization Server）**。
v0 只实现一条完整的纵向切片：`authorization_code` + **PKCE（S256，强制）** 流程，端到端可用，
签发可通过自身 JWKS 验证的 **RS256** access token 与 id token。

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
| GET | `/authorize` | `authorization_code` + PKCE(S256)，自动批准种子用户后 302 回跳 |
| POST | `/token` | 消费单次授权码，校验 PKCE 与绑定，返回 access/id token |
| GET | `/userinfo` | `Authorization: Bearer <access_token>`，返回 `{sub, email}` |

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
- **登录 / 同意 / Passkey / MFA / refresh token / social login**：v0 在 `/authorize` 直接自动批准种子用户
  `u_admin`（仅限 dev），位于清晰命名的 dev 路径后，后续可在不改变 wire 契约的前提下接入。
- **TLS**：v0 绑定明文 HTTP；TLS 由 Sluice/ACME 在前面终结（属未来接缝）。

> 安全提示：v0 的自动批准在无任何认证 / 同意的情况下为 `u_admin` 签发 token，**仅可用于 dev**。
