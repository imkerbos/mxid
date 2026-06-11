// Integration guides — Chinese content. Type definitions live in
// ./types.ts; per-language content files only export GUIDES.

import type { Guide } from './types'

export const GUIDES: Guide[] = [
  /* ─────────────── 部署 / Ops ─────────────── */
  {
    slug: 'prod-deploy',
    app: '生产环境部署',
    protocol: 'deploy',
    difficulty: 2,
    tags: ['部署', 'nginx', '单域名', 'TLS'],
    summary: 'MXID 推荐单域名 path-routing：一个 https 域名跑 portal + console + API + 协议端点。',
    steps: [
      {
        title: '1. 域名规划',
        body: `**单域名模型**（推荐 80% 场景）：

\`\`\`
https://id.example.com/             ← portal SPA（用户登录页）
https://id.example.com/admin/       ← console SPA（管理端）
https://id.example.com/api/         ← REST API
https://id.example.com/protocol/    ← OIDC / SAML / CAS endpoint
\`\`\`

issuer = portal_url = 同一个域名。OIDC \`iss\` claim 和 SAML EntityID 都用这个。

**关键约束**：\`issuer_url\` **必须** = portal 用户看到的域名，否则 RP 校验 \`iss\` 会失败。`,
      },
      {
        title: '2. 后端 config.prod.yaml',
        body: `\`\`\`yaml
server:
  port: 8080
  mode: release
  issuer_url:  "https://id.example.com"
  portal_url:  "https://id.example.com"
  console_url: "https://id.example.com/admin"

session:
  cookie_secure: true        # https 强制
  cookie_domain: "id.example.com"

crypto:
  # 32-byte AES-256 master key，必须用 env override
  # export MXID_CRYPTO_KEY_ENCRYPTION_KEY=<base64>
  key_encryption_key: ""
\`\`\``,
      },
      {
        title: '3. nginx 反向代理',
        body: `\`\`\`nginx
server {
  listen 443 ssl http2;
  server_name id.example.com;

  ssl_certificate     /etc/letsencrypt/live/id.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/id.example.com/privkey.pem;

  # —— Portal SPA build（用户登录页）——
  root /var/www/mxid/portal;
  index index.html;
  location / {
    try_files $uri /index.html;
  }

  # —— Console SPA build（管理端）——
  location /admin/ {
    alias /var/www/mxid/console/;
    try_files $uri $uri/ /admin/index.html;
  }

  # —— Backend（API + 协议 endpoint）——
  location ~ ^/(api|protocol|openapi)/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 60s;
  }
}

# HTTP → HTTPS 重定向
server {
  listen 80;
  server_name id.example.com;
  return 301 https://$host$request_uri;
}
\`\`\``,
      },
      {
        title: '4. 前端 build',
        body: `\`\`\`bash
# Portal
cd web/apps/portal
pnpm build
# 产出 dist/ → 拷到 /var/www/mxid/portal/

# Console
cd web/apps/console
pnpm build
# 产出 dist/ → 拷到 /var/www/mxid/console/
\`\`\`

**Console base path 调整**：因为部署在 \`/admin/\`，build 前在 \`vite.config.ts\` 设 \`base: '/admin/'\`，否则静态资源 404。`,
      },
      {
        title: '5. 双域名变体（可选）',
        body: `如果想把 console 放到独立域名（内网/VPN 限制）：

\`\`\`yaml
server:
  issuer_url:  "https://id.example.com"
  portal_url:  "https://id.example.com"
  console_url: "https://admin-id.example.com"
\`\`\`

\`admin-id.example.com\` 单独 nginx server block，root 指 console build，可加 IP 白名单 / mTLS。issuer 和 portal 保持原域名不变。

**注意**：跨域 cookie 不能共享 — console 和 portal 必须各自登录。当前实现 cookie 绑定到 \`portal_url\` 域，**双域名场景需要后续做 token 跨域桥接**（目前未实现，建议先用单域名）。`,
      },
      {
        title: '6. 验证清单',
        body: `\`\`\`
✓  https://id.example.com/                       portal 登录页
✓  https://id.example.com/admin/                 console 管理页
✓  https://id.example.com/api/v1/system/info     返回正确 URLs
✓  https://id.example.com/health                 backend 健康
✓  OIDC discovery（全局）：
    https://id.example.com/protocol/oidc/.well-known/openid-configuration
✓  SAML metadata（per app）：
    https://id.example.com/protocol/saml/<app_code>/metadata
✓  CAS login（per app）：
    https://id.example.com/protocol/cas/<app_code>/login?service=...
\`\`\`

\`system/info\` 输出应该是：
\`\`\`json
{
  "issuer_url":  "https://id.example.com",
  "portal_url":  "https://id.example.com",
  "console_url": "https://id.example.com/admin"
}
\`\`\``,
      },
    ],
    notes: [
      'crypto.key_encryption_key 务必用 env 注入，不要写进 yaml 提交仓库',
      'cookie_secure=true 后必须走 https，否则浏览器拒收 cookie 会全程登录失败',
      '反代必须传 X-Forwarded-Proto，否则 backend 生成的回调 URL 用 http 不是 https',
      '升级 console base path 后清浏览器缓存，否则旧 /assets/ 路径会 404',
    ],
  },

  /* ─────────────── 协议参考 ─────────────── */
  {
    slug: 'oidc-protocol-reference',
    app: 'OIDC 协议参考',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['协议', '参考', 'OpenID Connect'],
    summary: 'MXID 实现 OpenID Connect Core 1.0 + Discovery 1.0。端点全局共享，应用通过 client_id 区分。',
    steps: [
      {
        title: '1. Endpoint 总览',
        body: `所有 OIDC endpoint 在 MXID 是**全局**的（不带 app_code），多个应用共享同一组 URL，通过 \`client_id\` 区分。

\`\`\`
Issuer                {{ISSUER}}/protocol/oidc
Discovery             {{ISSUER}}/protocol/oidc/.well-known/openid-configuration
JWKS                  {{ISSUER}}/protocol/oidc/jwks

Authorize             {{ISSUER}}/protocol/oidc/authorize        GET / POST
Token                 {{ISSUER}}/protocol/oidc/token            POST
UserInfo              {{ISSUER}}/protocol/oidc/userinfo         GET / POST
Revocation            {{ISSUER}}/protocol/oidc/revoke           POST  (RFC 7009)
Introspection         {{ISSUER}}/protocol/oidc/introspect       POST  (RFC 7662)
End Session           {{ISSUER}}/protocol/oidc/end-session      GET   (OIDC RP-Initiated Logout)
\`\`\``,
      },
      {
        title: '2. Discovery 文档（OIDC Discovery 1.0）',
        body: `任何 OIDC RP 集成 MXID，第一步都是拉这一份 JSON：

\`\`\`bash
curl {{ISSUER}}/protocol/oidc/.well-known/openid-configuration
\`\`\`

关键字段：

\`\`\`json
{
  "issuer": "{{ISSUER}}/protocol/oidc",
  "authorization_endpoint": "{{ISSUER}}/protocol/oidc/authorize",
  "token_endpoint": "{{ISSUER}}/protocol/oidc/token",
  "userinfo_endpoint": "{{ISSUER}}/protocol/oidc/userinfo",
  "jwks_uri": "{{ISSUER}}/protocol/oidc/jwks",
  "end_session_endpoint": "{{ISSUER}}/protocol/oidc/end-session",
  "response_types_supported": ["code", "id_token", "code id_token"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public", "pairwise"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["openid", "profile", "email", "phone", "address", "offline_access"]
}
\`\`\``,
      },
      {
        title: '3. JWKS（签名公钥）',
        body: `RP 验证 id_token 签名时从这里拉公钥：

\`\`\`bash
curl {{ISSUER}}/protocol/oidc/jwks
\`\`\`

返回标准 JWK Set。MXID 用 RS256，每个租户独立密钥对（per-tenant rotation），\`kid\` 字段用于 RP 选择对应公钥。`,
      },
      {
        title: '4. Authorize 请求（典型 code flow + PKCE）',
        body: `\`\`\`
GET {{ISSUER}}/protocol/oidc/authorize?
    response_type=code
    &client_id=<your_client_id>
    &redirect_uri=<your_callback>
    &scope=openid+profile+email
    &state=<csrf_token>
    &code_challenge=<base64url(sha256(verifier))>
    &code_challenge_method=S256
    &nonce=<random>
\`\`\`

\`code_challenge_method=plain\` **不支持**（OAuth 2.1 BCP 强制 S256）。

公共客户端（SPA / 移动 app）：\`client_secret\` 留空，仅 PKCE 验证。`,
      },
      {
        title: '5. Token 交换',
        body: `\`\`\`bash
curl -X POST {{ISSUER}}/protocol/oidc/token \\
  -d "grant_type=authorization_code" \\
  -d "code=<from_callback>" \\
  -d "redirect_uri=<same_as_authorize>" \\
  -d "client_id=<id>" \\
  -d "client_secret=<secret>" \\
  -d "code_verifier=<original_verifier>"
\`\`\`

返回：\`access_token\`（JWT）、\`id_token\`（JWT）、\`refresh_token\`、\`expires_in\`、\`token_type=Bearer\`。`,
      },
      {
        title: '6. id_token 含 tenant_code',
        body: `多租户消歧：每个 id_token / userinfo 自动注入 \`tenant_code\` claim。

\`\`\`json
{
  "sub": "kerbos@solidleisure",
  "preferred_username": "kerbos",
  "email": "kerbos@solidleisure.com",
  "tenant_code": "solidleisure",
  "iss": "{{ISSUER}}/protocol/oidc",
  "aud": "<client_id>",
  "iat": 1733678400,
  "exp": 1733679300
}
\`\`\`

共享应用（cross-tenant）务必读 \`tenant_code\` 区分用户来源。`,
      },
      {
        title: '7. End Session（RP-Initiated Logout）',
        body: `\`\`\`
GET {{ISSUER}}/protocol/oidc/end-session?
    id_token_hint=<id_token>
    &post_logout_redirect_uri=<your_app_url>
    &state=<optional>
\`\`\`

会清除 MXID 端用户会话，然后重定向回 \`post_logout_redirect_uri\`。`,
      },
    ],
    notes: [
      'MXID 不发 plain JWT access_token —— access_token 也是 RS256 签名 JWT',
      'refresh_token 默认 168h（7 天），可在 config.jwt 调',
      '同一个用户在不同 app 下 sub 可能不同：subject_strategy=pairwise 会按 client_id hash',
    ],
  },
  {
    slug: 'saml-protocol-reference',
    app: 'SAML 协议参考',
    protocol: 'saml',
    difficulty: 2,
    tags: ['协议', '参考', 'SAML 2.0'],
    summary: 'MXID 实现 SAML 2.0 Web Browser SSO Profile。每个 SAML 应用一组 endpoint（per app_code）。',
    steps: [
      {
        title: '1. Endpoint 总览',
        body: `SAML endpoint **按 app_code 隔离**，每个应用有自己的 metadata / SSO / SLO URL。

\`\`\`
IDP Metadata          {{ISSUER}}/protocol/saml/<app_code>/metadata      GET
SSO Redirect          {{ISSUER}}/protocol/saml/<app_code>/sso           GET  (HTTP-Redirect binding)
SSO POST              {{ISSUER}}/protocol/saml/<app_code>/sso           POST (HTTP-POST binding)
SLO                   {{ISSUER}}/protocol/saml/<app_code>/slo           GET / POST
\`\`\`

把 \`<app_code>\` 换成 console 里创建应用时填的编码，例如 \`jira\` / \`confluence\` / \`aws\`。`,
      },
      {
        title: '2. IDP Metadata',
        body: `每个 SAML SP 配置时都需要 IDP metadata XML：

\`\`\`bash
curl {{ISSUER}}/protocol/saml/jira/metadata
\`\`\`

XML 包含：
- \`<EntityDescriptor entityID="{{ISSUER}}/protocol/saml/jira">\`
- \`<KeyDescriptor use="signing">\` 公钥
- \`<SingleSignOnService>\` Redirect + POST binding
- \`<SingleLogoutService>\`
- \`<NameIDFormat>\` 列表（emailAddress / persistent / transient）

**两种交付方式**：
1. **Metadata URL**（推荐）：把 \`{{ISSUER}}/protocol/saml/jira/metadata\` 直接给 SP，SP 会定时拉取更新
2. **Metadata XML**：浏览器打开 URL 下载 → 上传到 SP 配置`,
      },
      {
        title: '3. SP 端配置必填项',
        body: `给到 SP 管理员的清单：

\`\`\`
IDP Entity ID:        {{ISSUER}}/protocol/saml/<app_code>
SSO URL (Redirect):   {{ISSUER}}/protocol/saml/<app_code>/sso
SSO URL (POST):       {{ISSUER}}/protocol/saml/<app_code>/sso
SLO URL:              {{ISSUER}}/protocol/saml/<app_code>/slo
X.509 Cert:           从 metadata <ds:X509Certificate> 复制
NameID Format:        urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress (推荐)
Signature Algorithm:  RSA-SHA256
\`\`\`

console 端 app.\`protocol_config\` 填：
\`\`\`json
{
  "acs_url": "https://<sp-domain>/saml/acs",
  "sp_entity_id": "https://<sp-domain>",
  "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "attribute_mapping": {
    "email": "email",
    "display_name": "displayName"
  },
  "session_ttl": 28800
}
\`\`\``,
      },
      {
        title: '4. Attribute 默认输出',
        body: `每个 SAML Assertion 自动带：

\`\`\`xml
<saml:AttributeStatement>
  <saml:Attribute Name="username">
    <saml:AttributeValue>kerbos</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="email">
    <saml:AttributeValue>kerbos@solidleisure.com</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="display_name">
    <saml:AttributeValue>Kerbos</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="tenant_code">
    <saml:AttributeValue>solidleisure</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
\`\`\`

\`attribute_mapping\` 配置可以改 attribute name，例如 Jira 期望 \`displayName\` 不是 \`display_name\`。`,
      },
      {
        title: '5. SLO（Single Logout）',
        body: `两种触发方向：

**IDP-initiated**：用户在 MXID portal 登出 → MXID 向所有 SP 推送 LogoutRequest
**SP-initiated**：用户在 SP 登出 → SP 向 \`{{ISSUER}}/protocol/saml/<app_code>/slo\` 发 LogoutRequest → MXID 清 session → 回复 LogoutResponse

SLO 依赖 SP 端实现完整，很多商业 SaaS（如 Jira Cloud）不支持 SLO。`,
      },
      {
        title: '6. 验证 metadata',
        body: `部署完成后浏览器直接打开应该看到 XML：

\`\`\`
{{ISSUER}}/protocol/saml/<app_code>/metadata
\`\`\`

返回 \`404 application not found\` 说明 app_code 不存在 / 协议类型不是 SAML。`,
      },
    ],
    notes: [
      'Assertion 默认签名（不强制加密 —— 走 HTTPS 即可）',
      'SP 端 AuthnRequest 是否要求签名取决于 SP 配置；MXID 当前不强制校验入站签名',
      'NameID 形态由 subject_strategy 控制（email / persistent_id / username_suffixed）',
    ],
  },
  {
    slug: 'cas-protocol-reference',
    app: 'CAS 协议参考',
    protocol: 'cas',
    difficulty: 2,
    tags: ['协议', '参考', 'CAS 3.0'],
    summary: 'MXID 实现 CAS Protocol 3.0。Ticket 验证简洁，老 Java / Python 应用首选。',
    steps: [
      {
        title: '1. Endpoint 总览',
        body: `CAS endpoint **按 app_code 隔离**：

\`\`\`
Login                 {{ISSUER}}/protocol/cas/<app_code>/login            GET
Validate (CAS 1.0)    {{ISSUER}}/protocol/cas/<app_code>/validate         GET
Service Validate      {{ISSUER}}/protocol/cas/<app_code>/serviceValidate  GET   (CAS 2.0, XML)
P3 Service Validate   {{ISSUER}}/protocol/cas/<app_code>/p3/serviceValidate GET (CAS 3.0, XML + attributes)
Logout                {{ISSUER}}/protocol/cas/<app_code>/logout           GET
\`\`\`

**推荐 P3**：CAS 3.0 才能在 ServiceResponse 里带 attributes。`,
      },
      {
        title: '2. 典型流程',
        body: `1. 用户访问 SP 受保护资源 → SP 重定向到 MXID：
\`\`\`
{{ISSUER}}/protocol/cas/<app_code>/login?service=<SP_callback_url>
\`\`\`

2. MXID 登录 → 重定向回 SP，URL 带 ticket：
\`\`\`
<SP_callback_url>?ticket=ST-xxxxxxxx
\`\`\`

3. SP 后端拿 ticket 反向调 MXID 验证（带外验证，防伪）：
\`\`\`
GET {{ISSUER}}/protocol/cas/<app_code>/p3/serviceValidate?
    service=<SP_callback_url>
    &ticket=ST-xxxxxxxx
\`\`\`

4. MXID 返回 XML，含用户信息 + attributes。`,
      },
      {
        title: '3. P3 ServiceValidate 响应示例',
        body: `\`\`\`xml
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>kerbos</cas:user>
    <cas:attributes>
      <cas:email>kerbos@solidleisure.com</cas:email>
      <cas:display_name>Kerbos</cas:display_name>
      <cas:tenant_code>solidleisure</cas:tenant_code>
      <cas:groups>devops</cas:groups>
      <cas:groups>admins</cas:groups>
    </cas:attributes>
  </cas:authenticationSuccess>
</cas:serviceResponse>
\`\`\`

失败：

\`\`\`xml
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationFailure code="INVALID_TICKET">
    ticket not found or expired
  </cas:authenticationFailure>
</cas:serviceResponse>
\`\`\``,
      },
      {
        title: '4. Ticket 生命周期',
        body: `- **Service Ticket（ST）** \`ST-...\`：一次性，签发到验证 60s 内有效（可在 \`protocol_config.ticket_ttl\` 改）
- 验证一次后立即作废（防重放）
- 同一 service URL 重复登录会签发新 ticket，旧 ticket 不会自动失效（直到 TTL）

**安全要求**：service URL 必须在 app.\`service_urls\` 白名单内，否则 MXID 拒绝签发 ticket（防开放重定向）。`,
      },
      {
        title: '5. SP 端配置必填',
        body: `\`\`\`
CAS Server URL:       {{ISSUER}}/protocol/cas/<app_code>
CAS Protocol:         3.0（启用 P3）
Validate URL:         {{ISSUER}}/protocol/cas/<app_code>/p3/serviceValidate
Logout URL:           {{ISSUER}}/protocol/cas/<app_code>/logout
\`\`\`

console 端 app.\`protocol_config\`：
\`\`\`json
{
  "service_urls": ["https://<sp>/cas/callback"],
  "ticket_ttl": 60,
  "attribute_mapping": {
    "email": "mail",
    "display_name": "cn"
  }
}
\`\`\``,
      },
      {
        title: '6. 单点登出（CAS Logout）',
        body: `\`\`\`
GET {{ISSUER}}/protocol/cas/<app_code>/logout?service=<return_url>
\`\`\`

MXID 清 session 后重定向到 \`service\`（也必须在白名单）。

CAS 协议不支持反向通知 SP（不像 SAML SLO）。SP 需自己 poll session 或接受 ticket 失效。`,
      },
    ],
    notes: [
      'CAS 协议简单但不带签名 —— 安全完全依赖 HTTPS + service URL 白名单',
      'p3/serviceValidate 与 serviceValidate 的差异仅在 attributes —— 永远用 p3',
      'service URL 严格匹配（含 query string），不匹配直接 INVALID_SERVICE',
    ],
  },

  /* ─────────────── OIDC ─────────────── */
  {
    slug: 'jumpserver-cas',
    app: 'JumpServer',
    protocol: 'cas',
    difficulty: 2,
    tags: ['堡垒机', 'DevOps', 'CAS', '社区版', '实战验收'],
    summary: 'JumpServer v4 社区版 + CAS 全流程实战验收。社区版 OIDC/SAML 仅 EE，CAS 是最稳路径。',
    steps: [
      {
        title: '0. 协议选择',
        body: `\`\`\`
社区版（GPL）        CAS  ✓    OAuth2  ✓    LDAP  ✓    OIDC  ✗    SAML  ✗
企业版（EE）         CAS  ✓    OAuth2  ✓    LDAP  ✓    OIDC  ✓    SAML  ✓
\`\`\`

社区版唯一可用的成熟 SSO = **CAS**。`,
      },
      {
        title: '1. MXID Console 创建应用',
        body: `应用管理 → 新建应用：

- 协议：**CAS**
- 编码：自动生成的 \`app-xxxx\` 或自填（路径里就是这个）
- 名称：JumpServer
- **subject_strategy**：**必须显式选 \`username\`**

⚠️ **subject_strategy 坑**：协议默认值是 \`persistent_id\` (设置 → 协议默认值)，会输出用户内部 ID 数字串 (\`1\` \`2\`…) 作 CAS principal，JumpServer 拿到的用户名就是数字。建议:
- 私有 app：\`username\`
- 共享 app（跨 tenant）：\`username_suffixed\` 或 \`email\`

访问策略：至少加一条 \`allow public\`（让所有已登录用户能访问）。

**协议配置**（默认即可）：
\`\`\`json
{
  "service_urls": [],
  "ticket_ttl": 30,
  "attribute_mapping": {
    "username": "uid",
    "email": "mail",
    "display_name": "displayName",
    "phone": "telephoneNumber"
  }
}
\`\`\`

\`service_urls\` 留空 = 任意 service URL 放行（最方便）。要严格白名单就填 \`["http://<jumpserver>/core/auth/cas/login/"]\`。`,
      },
      {
        title: '2. MXID 端点（按 app_code 隔离）',
        body: `\`<APP>\` = 你在第 1 步看到的 \`code\` (e.g. \`app-u4zllixr\` 或自填 \`jumpserver\`)

\`\`\`
Server Root:   {{ISSUER}}/protocol/cas/<APP>/
Login:         {{ISSUER}}/protocol/cas/<APP>/login
P3 Validate:   {{ISSUER}}/protocol/cas/<APP>/p3/serviceValidate
Logout:        {{ISSUER}}/protocol/cas/<APP>/logout
\`\`\`

⚠️ **Server Root 必须末尾带 \`/\`**。django-cas-ng \`urljoin(SERVER_URL, "login")\` 走 RFC 3986 相对解析，没 \`/\` 会把最后一段 \`<APP>\` 当文件名替换成 \`login\` → 路径变成 \`/protocol/cas/login\` (缺 APP) → 404 application not found。`,
      },
      {
        title: '3. JumpServer Web 后台配置',
        body: `系统设置 → 认证设置 → **CAS** tab:

\`\`\`
CAS              ✓
服务端地址        {{ISSUER}}/protocol/cas/<APP>/    ← 末尾必带 /
回调地址          http://<your-jumpserver-public>   ← 根 URL 无路径
版本             3
映射属性          {"cas:user": "username", "mail": "email", "displayName": "name"}
同步注销          ✓
\`\`\`

⚠️ **服务端地址**: django-cas-ng \`urljoin(SERVER_URL, "login")\` 不加 \`/\` 会把 \`<APP>\` 当文件名替换成 \`login\` → URL 变成 \`/protocol/cas/login\` → 404。

⚠️ **回调地址**: 这是 \`CAS_ROOT_PROXIED_AS\` (反代场景 JumpServer 用它替换 request host 组装 service URL)。**不要带 \`/core/auth/cas/callback/\` 或 \`/core/auth/cas/login/\` 路径**，否则会双拼接成 \`/core/auth/cas/login//core/auth/cas/login/\`。

⚠️ **映射属性**: 默认只 \`{"cas:user": "username"}\` 不会拉 email/name。MXID p3/serviceValidate 默认 attribute_mapping 输出 \`uid mail displayName telephoneNumber\`, 上方加 \`mail/displayName\` 才同步。

提交后无需 JumpServer 重启 (settings 走 DB)，**MXID 这边也无需任何同步**。`,
      },
      {
        title: '4. v4 部署 — DOMAINS / 静态 / 单容器精简版',
        body: `JumpServer v4 部署有几个坑必须知道:

**① DOMAINS 必须**：v4 强制白名单访问的 host:port。缺这条登录页报 *"Configuration file has problems"*：

\`\`\`yaml
environment:
  DOMAINS: "localhost:4003,host.docker.internal:4003,192.168.x.x:4003"
  SITE_URL: "http://192.168.x.x:4003"
\`\`\`

**② core 自身不 serve /static**：必须 \`jumpserver/web:v4.x-ce\` (nginx) 共享同 volume \`/opt/jumpserver/data\` 才能 \`/static/*\` 200。

**③ 单容器精简模式**：v4 默认 nginx 配置硬引用 \`chen/koko/lion\` 上游，缺这些容器 nginx 启动 emerg。stub 解法：

\`\`\`yaml
jms-web:
  volumes:
    - ./empty.conf:/etc/nginx/includes/chen.conf:ro
    - ./empty.conf:/etc/nginx/includes/koko.conf:ro
    - ./empty.conf:/etc/nginx/includes/lion.conf:ro
\`\`\`

(\`empty.conf\` 内容就是注释)。资产终端连接功能不可用，但 Web UI + SSO 完整可用。

**④ network alias**：web 容器 nginx 配置硬编码上游名 \`core\`，需要把 service 暴露成 \`core\`：

\`\`\`yaml
jumpserver:
  networks:
    default:
      aliases:
        - core
\`\`\``,
      },
      {
        title: '5. 验证流程',
        body: `1. 浏览器无痕窗口 → \`http://<your-jumpserver>/\` 跳 \`/core/auth/login/\`
2. 点 **CAS 登录** → 302 跳 \`{{ISSUER}}/protocol/cas/<APP>/login?service=...\`
3. MXID portal /login 看到 \`?protocol=cas&app_code=<APP>&service=...\` query
4. 输 MXID 账号登录 → portal 检测到 SSO 流程 → \`window.location.replace\` 回 \`/protocol/cas/<APP>/login?...\` (proto session cookie 已 set)
5. backend 验 cookie → 签 ticket → 302 回 JumpServer \`/core/auth/cas/login/?ticket=ST-xxx\`
6. JumpServer 后端调 \`/p3/serviceValidate\` → 拿 \`cas:user\` + attributes → 自动建用户 (source = CAS) → 登入

成功标志：用户详情 source 字段 = **CAS** (不是 Local)。`,
      },
      {
        title: '6. Role / 用户组同步说明',
        body: `**JumpServer system_roles (System Admin / User / Auditor) 不能通过 CAS 自动映射**。CAS 协议本身没 role spec，JumpServer 也没暴露 role 映射 UI。

可行方案：
1. **手动**：admin 在 JumpServer 后台手动设. 适合 < 100 用户的 demo / 小团队
2. **用户组**：MXID app 协议配置加 \`attribute_mapping: {groups: groups}\`, JumpServer 端写 \`apps/authentication/backends/cas/views.py\` signal hook 把 CAS attr \`groups\` 同步到 JumpServer 用户组。维护成本高。
3. **EE 走 OIDC**：JumpServer EE 的 OIDC 集成支持 \`role_attribute_path\`，能从 \`groups\` claim 映射 role。

**用户已存在时 SSO 不覆盖属性**: JumpServer 把 CAS 用户名匹配到本地已有用户（如 admin），只走"代理登录"，不更新 email/name。要测属性同步必须**新建一个本地不存在的用户**走 SSO 自动建账号。`,
      },
      {
        title: '7. 企业版 OIDC (备选)',
        body: `**仅 JumpServer EE License**。MXID 换 OIDC 应用，Redirect URI:

\`\`\`
http://<jumpserver>/core/auth/oidc/callback/
\`\`\`

JumpServer 系统设置 → 认证设置 → OIDC:

\`\`\`
Base site URL            http://<jumpserver>
Provider Endpoint        {{ISSUER}}/protocol/oidc
Client ID                <MXID app.client_id>
Client Secret            <MXID app.client_secret>
Scopes                   openid profile email
\`\`\`

JumpServer 自动拉 \`{{ISSUER}}/protocol/oidc/.well-known/openid-configuration\`。`,
      },
    ],
    notes: [
      '⚠️ subject_strategy 默认 persistent_id 是平台级 default — 新建 CAS app 务必手动改 username, 否则 cas:user 是用户 ID 数字串',
      '⚠️ MXID 服务端地址必须 trailing slash, urljoin 相对解析坑',
      '⚠️ JumpServer 回调地址只填根 URL (无 path), 是 CAS_ROOT_PROXIED_AS 不是 callback path',
      'v4 必须 DOMAINS env. 缺这条登录页 "Configuration file has problems"',
      'service_urls 留空 = 任意 service 放行. 严格白名单要 HasPrefix 匹配整个 URL (含 query)',
      'CAS 1.0/2.0/3.0: 默认走 3.0 (p3/serviceValidate), 返回 XML + attributes',
      '社区版 CAS 不支持单点登出 (SLO) - JumpServer 注销不会 propagate 到 MXID',
      'system_roles 无法 CAS 自动映射, 手动 / 升级 EE 走 OIDC / 写 signal hook 三选一',
    ],
  },
  {
    slug: 'harbor-oidc',
    app: 'Harbor',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['容器', '镜像仓库', 'OIDC'],
    summary: 'Harbor v2.x 内置 OIDC 支持，自动按 group 建项目。',
    steps: [
      {
        title: '1. MXID 应用',
        body: `协议 OIDC / 编码 \`harbor\` / Redirect URI \`https://<harbor>/c/oidc/callback\`。

**关键**：编辑应用 → \`protocol_config\` 增加 claim mapper：

\`\`\`json
{
  "claim_mappers": [
    {"claim": "groups", "source": "user.groups.codes"},
    {"claim": "email", "source": "user.email"},
    {"claim": "name", "source": "user.display_name"}
  ]
}
\`\`\``,
      },
      {
        title: '2. Harbor 端',
        body: `Harbor Administration → Configuration → Authentication mode 选 **OIDC**：

\`\`\`
OIDC Provider name        MXID
OIDC Endpoint             {{ISSUER}}/protocol/oidc
OIDC Client ID            <client_id>
OIDC Client Secret        <client_secret>
Group claim name          groups
OIDC Admin Group          mxid-admins
Scope                     openid profile email offline_access
Verify Certificate        关闭（dev）
\`\`\``,
      },
      {
        title: '3. 验证',
        body: `点登录页 LOGIN WITH OIDC → MXID 授权 → 回到 Harbor。

Harbor 自动按用户的 groups claim 创建对应项目（如 \`mxid-admins\` 组有 admin 权限）。`,
      },
    ],
    notes: [
      'Harbor 要 offline_access scope 才能拿 refresh_token',
      'subject_strategy 推荐 persistent_id —— Harbor 永久绑定 sub',
    ],
  },
  {
    slug: 'grafana-oidc',
    app: 'Grafana',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['监控', '可观测', 'OIDC', '实战验收'],
    summary: 'Grafana generic_oauth provider, 5 分钟实战验收通过.',
    steps: [
      {
        title: '1. MXID 应用',
        body: `应用管理 → 新建应用：

- 协议：**OIDC**
- 编码：\`grafana\` 或自动生成 (不重要, grafana 不靠 code 路由)
- 名称：Grafana
- 客户端类型：**web_app** (confidential, 走 client_secret)
- subject_strategy：\`username\`
- Redirect URI: \`http://<grafana>/login/generic_oauth\` (容器场景: 用户浏览器看到的 URL, 例如 \`http://localhost:4000/login/generic_oauth\`)

访问策略：至少一条 \`allow public\` 或 \`allow group=grafana-users\`.

**协议配置 — 关键: 加 claim_mapper 把 groups 推到 userinfo**:

\`\`\`json
{
  "claim_mappers": [
    {"claim": "groups", "source": "user.groups.codes"}
  ]
}
\`\`\`

不加这一条, userinfo 默认没 \`groups\` 数组, Grafana 的 \`role_attribute_path\` 会拿不到 group 列表, role 永远 fallback Viewer.`,
      },
      {
        title: '2. Grafana 配置 (env 或 grafana.ini)',
        body: `**Docker compose env 形式** (推荐, 跟 grafana.ini 等价):

\`\`\`yaml
environment:
  GF_AUTH_GENERIC_OAUTH_ENABLED: "true"
  GF_AUTH_GENERIC_OAUTH_NAME: "MXID"
  GF_AUTH_GENERIC_OAUTH_CLIENT_ID: "<client_id>"
  GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: "<client_secret>"
  GF_AUTH_GENERIC_OAUTH_SCOPES: "openid profile email"
  GF_AUTH_GENERIC_OAUTH_USE_PKCE: "true"
  # 浏览器视角 = localhost
  GF_AUTH_GENERIC_OAUTH_AUTH_URL: "{{ISSUER}}/protocol/oidc/authorize"
  # server-to-server 视角 = host.docker.internal
  GF_AUTH_GENERIC_OAUTH_TOKEN_URL: "http://host.docker.internal:10050/protocol/oidc/token"
  GF_AUTH_GENERIC_OAUTH_API_URL: "http://host.docker.internal:10050/protocol/oidc/userinfo"
  GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP: "true"
  GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: "contains(groups[*], 'grafana-admins') && 'Admin' || 'Viewer'"
extra_hosts:
  - "host.docker.internal:host-gateway"
\`\`\`

⚠️ **auth_url 用 \`localhost\` (浏览器视角), token_url / api_url 用 \`host.docker.internal\` (容器视角)**。auth_url 是 302 给浏览器跟的, 必须浏览器可解析; token/api 是 grafana 后端发的 HTTP 请求, 容器内 \`localhost\` 是它自己, 必须走 \`host.docker.internal\`。`,
      },
      {
        title: '3. 验证',
        body: `1. 浏览器无痕访问 Grafana 登录页
2. 点 **Sign in with MXID** → 跳 MXID OIDC authorize → 输账号
3. consent (若开了 require_consent) → 跳回 grafana \`/login/generic_oauth\`
4. Grafana 后端调 \`/oidc/token\` + \`/oidc/userinfo\` → 拿 \`sub\` + \`groups\` → 自动建用户 + 按 \`role_attribute_path\` 算 role
5. 进 dashboard. Grafana \`Server Admin → Users\` 看新用户 role / login type = OAuth`,
      },
    ],
    notes: [
      '⚠️ MXID app 必须加 claim_mapper {claim:"groups", source:"user.groups.codes"}, 否则 userinfo 无 groups, Grafana 永远 Viewer',
      '⚠️ docker 环境下 auth_url=localhost, token/api=host.docker.internal (Linux 加 extra_hosts: host-gateway)',
      'role_attribute_path 是 JMESPath, contains(groups[*], "x") 检查 group code 命中',
      '默认 ALLOW_SIGN_UP=true 才会 SSO 自动建 grafana 用户. false 则需先手建',
      'subject_strategy=username 即可, grafana 用 sub 做唯一标识',
    ],
  },
  {
    slug: 'gitea-oidc',
    app: 'Gitea',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['Git', '代码托管', 'OIDC'],
    summary: 'Gitea OAuth2 Source，开源最常用的 SSO 接入。',
    steps: [
      {
        title: '1. MXID 应用',
        body: `协议 OIDC / 编码 \`gitea\` / Redirect URI \`https://<gitea>/user/oauth2/MXID/callback\``,
      },
      {
        title: '2. Gitea 后台',
        body: `Site Administration → Authentication Sources → Add：

\`\`\`
Type:              OAuth2
Auth Name:         MXID            ← 与回调 URL 中的名称必须一致
OAuth2 Provider:   OpenID Connect
Client ID:         <client_id>
Client Secret:     <client_secret>
OpenID Connect Auto Discovery URL:
   {{ISSUER}}/protocol/oidc/.well-known/openid-configuration
\`\`\``,
      },
    ],
  },

  /* ─────────────── SAML ─────────────── */
  {
    slug: 'jira-saml',
    app: 'Jira (Cloud / Data Center)',
    protocol: 'saml',
    difficulty: 2,
    tags: ['Atlassian', '协作', 'SAML'],
    summary: 'Atlassian 强制 SAML 2.0；NameID 必须用邮箱。',
    steps: [
      {
        title: '1. MXID 应用',
        body: `创建应用：

- 协议：**SAML**
- 编码：\`jira\`
- subject_strategy：**email**（Jira 用邮箱当 NameID）

编辑应用 → \`protocol_config\`：

\`\`\`json
{
  "acs_url": "https://<jira-domain>/plugins/servlet/samlconsumer",
  "sp_entity_id": "https://<jira-domain>",
  "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "attribute_mapping": {
    "email": "email",
    "display_name": "displayName",
    "username": "username"
  },
  "session_ttl": 28800
}
\`\`\``,
      },
      {
        title: '2. 拿 IDP Metadata',
        body: `\`\`\`
{{ISSUER}}/protocol/saml/jira/metadata
\`\`\`

浏览器打开下载 XML，或直接给 Jira metadata URL。`,
      },
      {
        title: '3. Jira 配置',
        body: `**Jira Cloud**：Settings → User Management → SAML → 上传 metadata XML

**Jira DC**：System → Authentication → SAML Authentication

填入：
\`\`\`
Single sign-on issuer       {{ISSUER}}
Identity provider single sign-on URL:
   {{ISSUER}}/protocol/saml/jira/sso
X.509 Certificate           <从 metadata 复制>
Username mapping            email
\`\`\``,
      },
      {
        title: '4. 验证',
        body: '退出 Jira → 访问任意页面 → 自动跳 MXID → 登录回跳 Jira。',
      },
    ],
    notes: [
      'Jira 强烈推荐 subject_strategy=email',
      '多 tenant 时，shared app 加 tenant_code attribute 让 Jira 区分用户来源',
    ],
  },
  {
    slug: 'confluence-saml',
    app: 'Confluence',
    protocol: 'saml',
    difficulty: 2,
    tags: ['Atlassian', '协作', 'SAML'],
    summary: 'Confluence 与 Jira 配置完全相同，只换 ACS URL。',
    steps: [
      {
        title: '1. MXID 应用',
        body: `同 Jira，编码改 \`confluence\`，ACS URL 改：

\`\`\`
https://<confluence-domain>/plugins/servlet/samlconsumer
\`\`\``,
      },
      {
        title: '2. Confluence 端',
        body: '一般用 Atlassian Crowd 或 Atlassian Access 中转。直接 metadata import 即可。',
      },
    ],
  },
  {
    slug: 'aws-saml',
    app: 'AWS Console',
    protocol: 'saml',
    difficulty: 3,
    tags: ['AWS', 'Cloud', 'SAML'],
    summary: 'AWS Identity Provider + IAM Role mapping，IAM 角色按 group 自动分配。',
    steps: [
      {
        title: '1. AWS IAM Identity Provider',
        body: `AWS Console → IAM → Identity providers → Add provider

- Provider type: **SAML**
- Provider name: MXID
- Metadata document: 上传 \`{{ISSUER}}/protocol/saml/aws/metadata\` 的内容`,
      },
      {
        title: '2. 建 IAM Role (Trust SAML)',
        body: `创建 IAM Role，Trust relationship 选「SAML 2.0 federation」→ 指向 MXID provider。

记下 Role ARN：\`arn:aws:iam::123456789012:role/MXIDUserRole\``,
      },
      {
        title: '3. MXID 应用 attribute',
        body: `协议 SAML / 编码 \`aws\` / protocol_config：

\`\`\`json
{
  "acs_url": "https://signin.aws.amazon.com/saml",
  "sp_entity_id": "urn:amazon:webservices",
  "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  "attribute_mapping": {
    "email": "https://aws.amazon.com/SAML/Attributes/RoleSessionName",
    "static.role": "arn:aws:iam::123:role/MXIDUserRole,arn:aws:iam::123:saml-provider/MXID"
  }
}
\`\`\`

AWS 要求 attribute name 用 full URN（与普通 SAML 不同）。`,
      },
    ],
    notes: ['AWS 必须用 RoleSessionName + Role 双 attribute', 'Session 默认 1h，可在 IAM Role 改'],
  },

  /* ─────────────── CAS ─────────────── */
  {
    slug: 'jenkins-cas',
    app: 'Jenkins',
    protocol: 'cas',
    difficulty: 2,
    tags: ['CI/CD', 'CAS'],
    summary: 'Jenkins CAS Plugin，老牌但稳定。',
    steps: [
      {
        title: '1. MXID 应用',
        body: `协议 **CAS** / 编码 \`jenkins\`

\`protocol_config\`：
\`\`\`json
{
  "service_urls": ["https://<jenkins>/securityRealm/finishLogin"],
  "ticket_ttl": 60,
  "attribute_mapping": {
    "email": "mail",
    "display_name": "cn",
    "username": "uid"
  }
}
\`\`\``,
      },
      {
        title: '2. Jenkins 装 CAS plugin',
        body: 'Manage Jenkins → Plugin Manager → 装「CAS Plugin」→ 重启',
      },
      {
        title: '3. 配置',
        body: `Manage Jenkins → Security → Security Realm 选 **CAS**：

\`\`\`
CAS Server URL:     {{ISSUER}}/protocol/cas/jenkins
CAS Protocol:       CAS 3.0
\`\`\``,
      },
    ],
  },

  /* ─────────────── Lark/Teams external login ─────────────── */
  {
    slug: 'lark-login',
    app: 'Lark / 飞书 登录 MXID 自己',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['Lark', '飞书', '第三方登录'],
    summary: '在 MXID Portal 加「使用 Lark 登录」按钮，员工免密码进。',
    steps: [
      {
        title: '1. Lark/飞书 开放平台建应用',
        body: `https://open.larksuite.com/app（国际版）或 https://open.feishu.cn/app（中国版）

- 创建「企业自建应用」
- 「凭证与基础信息」复制 **App ID** 和 **App Secret**
- 「安全设置」→ 重定向 URL 添加：
  \`\`\`
  {{ISSUER}}/api/v1/portal/auth/external/lark/callback
  \`\`\`
- 「权限管理」开通：获取用户基本信息 / 邮箱 / 手机号
- 「版本管理与发布」→ 发布或加测试人员`,
      },
      {
        title: '2. MXID Console 添加身份源',
        body: `侧栏「身份源」→「新增身份源」：

\`\`\`
类型     Lark (国际版) 或 飞书 (中国)
名称     Lark
编码     lark               ← 与回调 URL 末尾一致
App ID   <Lark 后台拷贝>
App Secret <Lark 后台拷贝>
启用     ✓
自动建用户 ✓
\`\`\`

**多租户**：先切到目标 tenant，再创建 IdP — IdP 自动归属当前 tenant。`,
      },
      {
        title: '3. 用户登录测试',
        body: `Portal 登录页：

\`\`\`
{{PORTAL}}/?tenant=<你的tenant-code>
\`\`\`

底部出现「Lark」按钮 → 点击 → 跳 Lark 授权 → 同意 → 回 MXID 自动建用户 → portal /apps 首页。`,
      },
    ],
    notes: [
      '邮箱不同 → 不同 user（不会自动合并）',
      '想合并：用「绑定外部身份」功能，从 portal 主动绑定（待开发）',
    ],
  },
]
