# Keystone

Keystone 是一个用 Rust（axum 0.8）实现的、符合标准的 **OIDC / OAuth2 授权服务器（Authorization Server）**。
v0 只实现一条完整的纵向切片：`authorization_code` + **PKCE（S256，强制）** 流程，端到端可用，
签发可通过自身 JWKS 验证的 **RS256** access token 与 id token。

## 它是什么

- 默认开发监听：`127.0.0.1:8080`，issuer = `http://127.0.0.1:8080`
- 公开客户端（public client，无 client secret），安全性依赖 **redirect_uri 精确匹配** + **单次使用、PKCE 绑定的授权码**
- 启动时生成一对 RSA-2048 密钥，常驻 `Arc<SigningKey>`；`kid` 采用 RFC 7638 JWK thumbprint，
  保证 JWKS 中的 `kid` 与 JWT header 中的 `kid` 永不漂移

## 如何运行

```bash
# 构建
cargo build

# 运行（监听 127.0.0.1:8080）
cargo run

# 测试（含端到端契约测试）
cargo test
```

冒烟验证（服务运行后）：

```bash
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/.well-known/openid-configuration | jq .
curl -s http://127.0.0.1:8080/jwks.json | jq .
```

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
- **存储是可插拔的 `Store` trait**：v0 用 `InMemoryStore`（`Mutex<HashMap>`），方法
  `get_client / get_user / put_code / take_code`（原子单次消费）。handler 不接触任何具体存储类型。
- **PKCE S256 强制**：`/authorize` 缺少 `code_challenge` 或 `code_challenge_method != S256` 一律 400；
  `/token` 重算 `base64url(sha256(verifier))` 与存储的 challenge 比对。无 plaintext PKCE，无 implicit/hybrid。
- 授权码为 32 字节 CSPRNG 不透明值，单次使用，60s TTL，绑定 `client_id + redirect_uri + code_challenge + sub + nonce + scope`。

## 已延后（deferred / TODO seam）

- **FusionDB 后端存储**：当前仅 `InMemoryStore`；`store.rs` 中标注了 `FusionDbStore` 的 TODO 接缝。
  FusionDB **未运行**，v0 不依赖它。
- **密钥持久化 / 轮换**：当前每次启动生成一对密钥并常驻内存；`keys.rs` 标注了从 FusionDB/HSM 加载/轮换的 TODO 接缝。
- **登录 / 同意 / Passkey / MFA / refresh token / social login**：v0 在 `/authorize` 直接自动批准种子用户
  `u_admin`（仅限 dev），位于清晰命名的 dev 路径后，后续可在不改变 wire 契约的前提下接入。
- **TLS**：v0 绑定明文 HTTP；TLS 由 Sluice/ACME 在前面终结（属未来接缝）。

> 安全提示：v0 的自动批准在无任何认证 / 同意的情况下为 `u_admin` 签发 token，**仅可用于 dev**。
