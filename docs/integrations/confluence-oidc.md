# Confluence 接入 MXID（OIDC）

Confluence Data Center 通过 **OIDC** 接 MXID。本文按实际排障顺序写，每一节对应一个真实踩过的坑。

## 0. 前提

- MXID 后端已处理 `X-Forwarded-Proto` + `trusted_proxies`（见 [接入总览](README.md#部署前提接第一个应用前必看)）。
- Confluence 有一个外部可达的 **HTTPS** 地址（下记 `<CONFLUENCE>`）。
- 用的是 Atlassian 官方的 **SSO for Atlassian Data Center**（回调路径 `/plugins/servlet/oidc/callback`）。第三方插件（resolution、miniOrange）配置项名称不同，但下面三个坑同样适用。

## 1. MXID 侧建应用

console → 应用管理 → 新建 OIDC 应用：

| 字段 | 值 |
|---|---|
| Redirect URI | `<CONFLUENCE>/plugins/servlet/oidc/callback` |
| Scopes | `openid profile email` |

记下 `client_id` / `client_secret`。

建完再进 **应用详情 → 协议配置**，把 **ID Token 携带身份声明**（`id_token_userinfo_claims`）设为 `true` —— 见第 3 节，不开这个必失败。新建表单里没有这一项，只能建完再改。

## 2. Confluence 侧配置

Administration → Security → **Authentication methods** → 添加 OpenID Connect。

自动发现填：`<HOST>/protocol/oidc/.well-known/openid-configuration`

**必须打开 Just-in-time provisioning（自动创建用户）**，否则第一次登录的用户会被拒：

```
Received SSO request for user <username>, but the user does not exist
```

Confluence 的 SSO 只负责认证，不负责建号。用户没在 Confluence 里存在过就登不进去。

JIT 打开后还有两个前置条件，不满足会"开了也没用"：

- **用户目录必须可写。** 接的是只读 LDAP / Crowd 的话 JIT 无处建号。查 Administration → User Directories，确保有 Internal Directory 且顺序靠前。
- **新建用户要有组和 license seat。** 插件里配置默认加入 `confluence-users`，否则人建出来了进不去空间，或者超 license 直接失败。

## 3. 关键：ID Token 必须携带 email

**这是最容易卡住的一步，且报错信息不会告诉你原因。**

现象：JIT 已打开，登录仍然失败：

```
JitException: Claim [email] could not be found
    at OidcUserDataFromIdpMapper.mapUser(OidcUserDataFromIdpMapper.java:44)
```

原因：**Confluence 的 JIT mapper 只读 id_token，从不调用 userinfo 端点。** 而 MXID 默认把身份声明（`email` / `name` / `phone` / `locale`）只放在 userinfo，id_token 里只有 `sub` / `preferred_username` / `tenant_code` / `groups` / `sid`。

这个默认对规范友好（id_token 更小，合规的 RP 会自己去取 userinfo），但 Confluence 不是那种 RP，而且它没有开关可以改。

解法：在 MXID 的应用配置里把 **`id_token_userinfo_claims`** 设为 `true`。开启后 id_token 会同时带上：

```
email, email_verified, name, phone_number, phone_number_verified, locale, updated_at
```

userinfo 端点的返回不受影响。

**只给需要的应用开。** 两个原因：

1. id_token 会经过浏览器、并落进 RP 的日志，而 userinfo 的返回不会 —— 开了就等于扩大泄露面。
2. 开关放行的不止上面七个 claim。它同时让 `profile` / `email` / `phone` / `address` 这几个 scope 重新进入 claim mapper 的匹配范围，所以**应用里配的、绑定在这些 scope 上的 `claim_mappers`（包括 `user.detail.*` 自定义字段）也会开始写进 id_token**。配过 mapper 的应用开这个开关前先看一眼自己配了什么。

### 怎么确认某个 SP 到底调不调 userinfo

看 MXID 侧访问日志，按来源 IP 分组：

```bash
kubectl logs -n <ns> statefulset/mxid --all-containers --since=3h \
  | jq -r 'select(.path | test("^/protocol/oidc/(token|userinfo)$")) | "\(.clientIp) \(.path)"' \
  | sort | uniq -c | sort -rn
```

同一个 SP 的 IP 只出现 `/token`、从不出现 `/userinfo` —— 那它就只读 id_token，需要开这个开关。

> `clientIp` 要有意义，前提是 `trusted_proxies` 已按第 0 节配好；没配的话所有请求的来源 IP 都是 LB 那一个，分不出是谁。

## 4. 用户名映射

MXID 发出的 `preferred_username` 就是 MXID 里的用户名原文。如果 Confluence 侧已有同名用户但大小写不同（`Paco.Sun` vs `paco.sun`），匹配会失败。

**注意 `sub` 默认不是用户名。** OIDC 的 `subject_strategy` 出厂默认是 `persistent_id` —— 一个不透明的雪花 ID，改名也不变（在 设置 → 协议默认值 里改，应用可单独覆盖）。拿 `sub` 当账号名建号的话，Confluence 里会出现一堆纯数字用户名。

两个选择：

- 让 Confluence 用 **email** 匹配用户（Atlassian 生态本来就以邮箱为主键，最稳）
- 或在 MXID 应用里把 `subject_strategy` 改成 `email`，`sub` 直接就是邮箱

> 选 `email` 的话，先确认所有会登这个应用的用户都填了邮箱：没邮箱的用户解析失败会**静默回退成雪花 ID**，不会报错，表现就是个别用户莫名建出数字账号。

## 5. MXID 通过 OIDC 能提供的全部用户信息

| claim | 所属 scope | 默认位置 |
|---|---|---|
| `sub` | 总是 | id_token + userinfo |
| `preferred_username` | 总是 | id_token + userinfo |
| `tenant_code` | 总是（有应用配置时） | id_token + userinfo |
| `groups` | `groups` | id_token + userinfo |
| `app_roles` | 总是（配了角色时） | id_token + userinfo |
| `sid` | 总是 | id_token |
| `name` | `profile` | **仅 userinfo** |
| `picture` | `profile` | **仅 userinfo** |
| `email` / `email_verified` | `email` | **仅 userinfo** |
| `phone_number` / `phone_number_verified` | `phone` | **仅 userinfo** |
| `locale` / `updated_at` | `profile` | **仅 userinfo** |

标记"仅 userinfo"的那些，开启 `id_token_userinfo_claims` 后会同时出现在 id_token。

用户没填的字段整个 claim 不出现（不是空字符串）—— 例如没邮箱的用户，`email` 这个键压根不在返回里。**两个例外**：`preferred_username` 恒定下发；`locale` 没填时下发默认值 `zh-CN` 而不是省略。

`groups` 只要请求了 `groups` scope 就有，**不需要配 claim mapper**。

## 6. 排障速查

| 报错 | 原因 | 处理 |
|---|---|---|
| `user does not exist` | JIT 没开 | 第 2 节 |
| `Claim [email] could not be found` | Confluence 只读 id_token | 第 3 节，开 `id_token_userinfo_claims` |
| JIT 开了仍报 user does not exist | 目录只读 / 缺组或 license | 第 2 节末尾两条 |
| 用户能登录但无权限 | 新建用户没进 `confluence-users` | 插件的默认组配置 |
