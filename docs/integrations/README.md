# 应用接入总览

MXID 支持三种 SSO 协议：**OIDC / SAML / CAS**。本目录是各应用的接入手册。

## OIDC（推荐）

OIDC 引擎基于 [`zitadel/oidc`](https://github.com/zitadel/oidc) v3，是标准、维护活跃的 OpenID Connect Provider。**优先用 OIDC**（比 SAML/CAS 更现代、配置更简单、支持后台通道登出）。

### 关键端点

以 `https://<你的域名>`（即 issuer 根，下面记作 `<HOST>`）为例：

| 名称 | 地址 |
|------|------|
| **Discovery** | `<HOST>/protocol/oidc/.well-known/openid-configuration` |
| **issuer (`iss`)** | `<HOST>/protocol/oidc` ← 注意带 `/protocol/oidc` 后缀 |
| authorization | `<HOST>/protocol/oidc/authorize` |
| token | `<HOST>/protocol/oidc/token` |
| userinfo | `<HOST>/protocol/oidc/userinfo` |
| jwks | `<HOST>/protocol/oidc/jwks` |
| end_session（登出） | `<HOST>/protocol/oidc/end-session` |
| revocation / introspection | `<HOST>/protocol/oidc/revoke` · `/introspect` |

> **接入时优先填 Discovery URL**（自动发现），不要手填各端点——省事且不会填错。绝大多数客户端只需要 Discovery URL + client_id + client_secret。

### 能力矩阵（当前引擎）

| 项 | 支持情况 |
|----|----------|
| response_type | **仅 `code`**（授权码 + PKCE S256）。implicit 已弃用（OAuth 2.1） |
| grant_type | `authorization_code`、`refresh_token`、`client_credentials`（机器对机器） |
| 客户端认证 | `client_secret_basic`、`client_secret_post`、`private_key_jwt`、`none`(公有客户端+PKCE) |
| **不支持** | `client_secret_jwt`（HS256）—— 密钥单向 bcrypt 存储，无法 HMAC；请用 `private_key_jwt` |
| refresh token | 需请求 **`offline_access`** scope 才会签发 |
| 后台通道登出 | 支持（`backchannel_logout_supported`）——离职/JIT 到期会强制登出下游应用 |

### 常用 scope 与 claim

- **scope**：`openid profile email groups`（`offline_access` 换 refresh token）
- **id_token / userinfo 里的 claim**：
  - `sub`：主体标识（OIDC 默认 = `persistent_id`，不透明且改名后不变；可在应用里改为
    username/username_suffixed/pairwise/email）。SAML NameID 与 CAS `cas:user` 默认 = 用户名，
    因为下游应用拿它当账号名建号。
  - `groups`：用户所属组的 code 列表 —— 请求 `groups` scope 即可，**不需要 claim mapper**
  - `app_roles`：用户在**本应用**的角色 code 列表（给 RP 直接做角色映射，比解析 groups 省事）
  - `tenant_code`、`preferred_username`、`email` / `email_verified`、`name`、`amr`、`sid`

> 要让 `groups` 出现在 token，把 `groups` 加进应用的 scope 列表即可。
>
> claim mapper 只在需要**换个 claim 名**、或取下面这些非标准字段时才用。合法 source：
>
> - 两段式 `user.<字段>`：`user.groups`、`user.email`、`user.phone`、`user.username`、
>   `user.display_name`、`user.avatar`、`user.locale`、`user.status`、`user.tenant_id`、
>   `user.updated_at`、`user.id`、`user.id_string`
> - 三段式 `user.detail.<列名>`：`employee_no`、`job_title`、`department`、`gender`、
>   `birthday`、`address`（来自 `mxid_user_detail`）
> - 四段式 `user.identity.<provider>.<字段>`：外部身份（飞书 / Teams / GitHub…）的 ID。
>   provider 是 `lark` / `feishu` / `teams` / `github` 这类 provider_type；
>   字段只有三个：`external_id`、`user_id`、`union_id`。
>   **故意只开放 ID 字段** —— IdP 返回的完整 profile 还含邮箱、手机、姓名、
>   职位、办公地点，放开任意 key 等于把每应用配置变成数据导出接口。
>
>   **字段名按 provider 不同，不要照抄另一个 provider 的配置**：
>
>   | provider | 用这个 | 是什么 | 注意 |
>   |---|---|---|---|
>   | `lark` / `feishu` | `user.identity.lark.user_id` | 飞书的企业内通用 user_id | `external_id` 是 open_id（按应用区分，跨应用不通用）；`union_id` 也在 |
>   | `teams` | `user.identity.teams.external_id` | Entra objectId（36 位 UUID） | **`user_id` / `union_id` 在 Teams 上永远为空** —— 那是飞书的字段名 |
>
>   Teams 群里 @ 人，bot 侧要的往往是 `29:` 开头的**会话成员 id**，那是 Teams
>   的会话状态，SSO 拿不到也不该拿。用这里给的 objectId 自行换取。
>
> **`user.id` 对 JS 客户端是坏的**：snowflake ≈ 3.9×10¹⁷ 超过 2^53，`JSON.parse`
> 会返回一个邻近的整数。新配置一律用 `user.id_string`；`user.id` 只为兼容既有应用保留。
>
> **路径写错不会报错，只会没有这条 claim。** 不在上面列表里的一律静默忽略 ——
> 比如三段式的 `user.groups.codes`（console 的接入指南曾经错写过它好几个月）。

### 登录确认行为

- **SP 发起**（第三方应用把用户跳转过来）：每次登录都会显示一次「登录到 App X？」确认页（Google 风格）。
- **IdP 发起**（用户从 MXID 门户点应用图标进）：无感直登。

## 部署前提（**接第一个应用前必看**）

MXID 后端在 TLS 边缘（GKE Gateway / nginx / LB）后面时，有两个坑必须先处理，否则 OIDC 会 403 / 用户会莫名 429：

1. **`X-Forwarded-Proto: https` 必须传到后端。** TLS 在边缘卸载后，后端收到的是明文 http；zitadel 引擎会拿它跟 https 的 issuer 比对，不匹配就 **403**（discovery/authorize 全挂）。
   - GKE Gateway API：在 HTTPRoute 的后端路由加 `RequestHeaderModifier` set `X-Forwarded-Proto: https`（Helm 值 `routing.forwardedProtoHttps`）。
   - nginx：`location /protocol/` 里显式 `proxy_set_header X-Forwarded-Proto $scheme;`（一旦 location 内设了任何 proxy_set_header，继承的头会全丢，要重新声明）。
2. **配 `trusted_proxies`**（Helm 值 `config.trustedProxies`）。不配的话所有客户端的真实 IP 被压扁成 LB 的一个 IP，共用一个限流桶 → 整个办公室/集群一起 **429**。GKE 抄 `130.211.0.0/22`、`35.191.0.0/16` + 你的 Pod CIDR。

## 各应用接入手册

- [Jenkins（OIDC）](jenkins-oidc.md)
- [Confluence（OIDC）](confluence-oidc.md) — 需开 `id_token_userinfo_claims`，它只读 id_token 不调 userinfo
- Grafana（OIDC）：demo 见 `~/Workspaces/Docker/demo`（generic_oauth）
- JumpServer：仅社区版 **CAS**（见 [[reference_app_protocol_support]] 备注）

## SAML / CAS

SAML、CAS 引擎按**应用分段**挂载：

- SAML metadata：`<HOST>/protocol/saml/<app>/metadata`
- CAS：`<HOST>/protocol/cas/<app>/login`、`/serviceValidate`

（裸 `/protocol/saml/metadata`、`/protocol/cas/login` 会 404 —— 必须带应用标识段。）
