// Integration guides — English content. Mirrors guides.zh.ts slug-by-slug.
//
// Translation policy:
// - Grafana / JumpServer (the two end-to-end verified integrations) carry
//   full English step bodies.
// - The remaining guides currently provide English titles + summaries +
//   notes only, with a Chinese-fallback callout in the first step. The
//   intent is to fill them out incrementally as each integration is
//   re-verified in an English-language environment.
//
// The page (index.tsx) renders this list when i18n.language is not zh-*.

import type { Guide } from './types'

const FALLBACK_BODY = `> 🇨🇳 Detailed walkthrough has not been translated yet. Switch the console
> language to 中文 for the full Chinese version, or follow the bullet
> outline above.`

export const GUIDES: Guide[] = [
  /* ─────────────── Deploy / Ops ─────────────── */
  {
    slug: 'prod-deploy',
    app: 'Production deployment',
    protocol: 'deploy',
    difficulty: 2,
    tags: ['Deploy', 'nginx', 'Single domain', 'TLS'],
    summary: 'MXID recommends a single-domain path-prefix layout: one HTTPS domain serves portal + console + API + protocol endpoints.',
    steps: [
      {
        title: 'Layout',
        body: `Recommended routing (matches Keycloak / GitLab convention):

\`\`\`
https://<host>/             → portal SPA
https://<host>/admin/       → console SPA
https://<host>/api/v1/...   → backend REST
https://<host>/protocol/... → backend SSO endpoints
https://<host>/static/...   → backend static
https://<host>/health       → liveness
\`\`\`

Same scheme dev and prod, only the host changes.

${FALLBACK_BODY}`,
      },
    ],
    notes: [
      'Two-pod runtime: nginx (TLS, SPA static) + backend (Go binary).',
      'See docs/DEPLOYMENT.md for the production checklist.',
    ],
  },

  /* ─────────────── Protocol references ─────────────── */
  {
    slug: 'oidc-protocol-reference',
    app: 'OIDC protocol reference',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['Protocol', 'Reference', 'OpenID Connect'],
    summary: 'MXID implements OpenID Connect Core 1.0 + Discovery 1.0. Endpoints are globally shared; apps are distinguished by client_id.',
    steps: [
      {
        title: 'Endpoints',
        body: `\`\`\`
Discovery:    {{ISSUER}}/protocol/oidc/.well-known/openid-configuration
JWKS:         {{ISSUER}}/protocol/oidc/jwks
Authorize:    {{ISSUER}}/protocol/oidc/authorize
Token:        {{ISSUER}}/protocol/oidc/token
UserInfo:     {{ISSUER}}/protocol/oidc/userinfo
Revoke:       {{ISSUER}}/protocol/oidc/revoke
Introspect:   {{ISSUER}}/protocol/oidc/introspect
End session:  {{ISSUER}}/protocol/oidc/end-session
\`\`\`

${FALLBACK_BODY}`,
      },
    ],
    notes: [
      'Supported flows: Authorization Code + PKCE, Refresh, Client Credentials, Implicit (legacy), Hybrid.',
      'Subject strategies: username, username_suffixed, email, persistent_id, pairwise.',
      'Effective app roles ship as the `app_roles` claim (string array) in id_token + userinfo. JIT-elevated roles come first (app_roles[0]); an expired grant drops out automatically. Single-primary-role SPs read app_roles[0]; permission-union SPs iterate the whole array.',
    ],
  },
  {
    slug: 'saml-protocol-reference',
    app: 'SAML protocol reference',
    protocol: 'saml',
    difficulty: 2,
    tags: ['Protocol', 'Reference', 'SAML 2.0'],
    summary: 'MXID implements SAML 2.0 Web Browser SSO Profile. Each SAML app gets its own set of endpoints (per app_code).',
    steps: [
      {
        title: 'Endpoints',
        body: `\`\`\`
Metadata:  {{ISSUER}}/protocol/saml/<app_code>/metadata
SSO:       {{ISSUER}}/protocol/saml/<app_code>/sso       (POST + Redirect bindings)
SLO:       {{ISSUER}}/protocol/saml/<app_code>/slo
\`\`\`

${FALLBACK_BODY}`,
      },
    ],
    notes: [
      'Assertions signed with SHA-256.',
      'EntityID equals the issuer URL.',
      'Effective app roles ship as a multi-value attribute named by `role_attribute` (default `roles`; set `memberOf`/`groups`/`Role` to match the SP). JIT-elevated roles come first; an expired grant drops out automatically.',
    ],
  },
  {
    slug: 'cas-protocol-reference',
    app: 'CAS protocol reference',
    protocol: 'cas',
    difficulty: 2,
    tags: ['Protocol', 'Reference', 'CAS 3.0'],
    summary: 'MXID implements CAS Protocol 3.0. Ticket validation is straightforward; legacy Java / Python apps usually pick CAS.',
    steps: [
      {
        title: 'Endpoints',
        body: `\`\`\`
Login:              {{ISSUER}}/protocol/cas/<app_code>/login
serviceValidate:    {{ISSUER}}/protocol/cas/<app_code>/serviceValidate     (CAS 2.0)
p3/serviceValidate: {{ISSUER}}/protocol/cas/<app_code>/p3/serviceValidate  (CAS 3.0 + attributes)
Logout:             {{ISSUER}}/protocol/cas/<app_code>/logout
\`\`\`

${FALLBACK_BODY}`,
      },
    ],
    notes: [
      'CAS 3.0 returns XML with <cas:user> and <cas:attributes>.',
      'service_urls allow-list in protocol_config defaults to wide-open ([]).',
      'Effective app roles ship as multi-value <cas:roles> elements (name configurable via `role_attribute`, default `roles`). JIT-elevated roles come first; an expired grant drops out automatically.',
    ],
  },

  /* ─────────────── JumpServer (verified) ─────────────── */
  {
    slug: 'jumpserver-cas',
    app: 'JumpServer',
    protocol: 'cas',
    difficulty: 2,
    tags: ['Bastion', 'DevOps', 'CAS', 'Community Edition', 'Verified'],
    summary: 'JumpServer v4 community edition + CAS — end-to-end verified. OIDC / SAML are EE-only on JumpServer; CAS is the safest community-edition path.',
    steps: [
      {
        title: '0. Protocol choice',
        body: `\`\`\`
Community (GPL)   CAS  ✓    OAuth2  ✓    LDAP  ✓    OIDC  ✗    SAML  ✗
Enterprise (EE)   CAS  ✓    OAuth2  ✓    LDAP  ✓    OIDC  ✓    SAML  ✓
\`\`\`

The only mature SSO available on the community edition is **CAS**.`,
      },
      {
        title: '1. Create the MXID app',
        body: `Apps → New app:

- Protocol: **CAS**
- Code: autogenerated \`app-xxxx\` or your own (whatever you type ends up in the URL path).
- Name: JumpServer
- **subject_strategy**: **set this to \`username\` explicitly**.

⚠️ **subject_strategy pitfall**: the platform default (Settings → Protocol defaults) is \`persistent_id\`, which emits the internal numeric user ID (\`1\`, \`2\`, …) as the CAS principal. JumpServer would then show your username as a digit. Pick:
- Tenant-private app: \`username\`
- Shared app (across tenants): \`username_suffixed\` or \`email\`

Access policy: add at least one \`allow public\` rule (or scope it tighter).

**Protocol config** (defaults fine):
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

Leaving \`service_urls\` empty allows any service URL — easiest. Tighten to \`["http://<jumpserver>/core/auth/cas/login/"]\` for a strict allow-list.`,
      },
      {
        title: '2. MXID endpoints (per app_code)',
        body: `\`<APP>\` = the \`code\` from step 1 (e.g. \`app-u4zllixr\` or your own \`jumpserver\`).

\`\`\`
Server root:    {{ISSUER}}/protocol/cas/<APP>/
Login:          {{ISSUER}}/protocol/cas/<APP>/login
P3 Validate:    {{ISSUER}}/protocol/cas/<APP>/p3/serviceValidate
Logout:         {{ISSUER}}/protocol/cas/<APP>/logout
\`\`\`

⚠️ **The server root MUST end with a slash**. django-cas-ng calls \`urljoin(SERVER_URL, "login")\`, and per RFC 3986 the trailing slash decides whether the last path segment is treated as a file (which gets replaced by \`login\`) or a directory (which preserves it). Drop the slash and you end up requesting \`/protocol/cas/login\` (no APP) → 404 application not found.`,
      },
      {
        title: '3. JumpServer admin settings',
        body: `System settings → Authentication → **CAS** tab:

\`\`\`
CAS              ✓
Server URL       {{ISSUER}}/protocol/cas/<APP>/    ← trailing slash required
Callback URL     http://<your-jumpserver-public>   ← root URL, NO path
Version          3
Attribute map    {"cas:user": "username", "mail": "email", "displayName": "name"}
Sync logout      ✓
\`\`\`

⚠️ **Server URL**: see step 2 — without the trailing slash django-cas-ng strips \`<APP>\` from the path.

⚠️ **Callback URL**: this is \`CAS_ROOT_PROXIED_AS\` (used as the base host when JumpServer assembles the service URL behind a proxy). It is **NOT** a callback path. Do not append \`/core/auth/cas/callback/\` or \`/core/auth/cas/login/\` — JumpServer would then build \`/core/auth/cas/login//core/auth/cas/login/\`.

⚠️ **Attribute map**: the default \`{"cas:user": "username"}\` only pulls the username. To sync email + display name, expand the map as shown. MXID's p3/serviceValidate exposes \`uid mail displayName telephoneNumber\` by default.

JumpServer does **not** need a restart after saving (settings live in DB). MXID does not need any sync action.`,
      },
      {
        title: '4. v4 deployment pitfalls — DOMAINS / static / single-container web stubs',
        body: `Three issues bite first-time JumpServer v4 operators:

**① DOMAINS is mandatory in v4.** Without it the login page renders the error *"Configuration file has problems"*:

\`\`\`yaml
environment:
  DOMAINS: "localhost:4003,host.docker.internal:4003,192.168.x.x:4003"
  SITE_URL: "http://192.168.x.x:4003"
\`\`\`

**② The core container does not serve /static.** Mount the SAME data volume into both core and \`jumpserver/web:v4.x-ce\` (the nginx fronting it) so \`/static/*\` resolves.

**③ Single-container slimming.** The default web nginx config references upstreams named \`chen\` / \`koko\` / \`lion\`. Without those containers nginx fails to start with *"host not found in upstream"*. Stub the includes:

\`\`\`yaml
jms-web:
  volumes:
    - ./empty.conf:/etc/nginx/includes/chen.conf:ro
    - ./empty.conf:/etc/nginx/includes/koko.conf:ro
    - ./empty.conf:/etc/nginx/includes/lion.conf:ro
\`\`\`

(\`empty.conf\` contains a single comment line.) Asset terminal connections will be unavailable, but the Web UI + SSO work end-to-end.

**④ Network alias** so JumpServer's nginx finds its core upstream by name:

\`\`\`yaml
jumpserver:
  networks:
    default:
      aliases:
        - core
\`\`\``,
      },
      {
        title: '5. Verification flow',
        body: `1. Incognito window → \`http://<your-jumpserver>/\` → JumpServer redirects to \`/core/auth/login/\`.
2. Click **CAS Login** → 302 to \`{{ISSUER}}/protocol/cas/<APP>/login?service=...\`.
3. MXID portal /login receives \`?protocol=cas&app_code=<APP>&service=...\` in its query string.
4. Sign in with an MXID account → portal detects the SSO handshake → \`window.location.replace\` back to \`/protocol/cas/<APP>/login?...\` (with the proto session cookie set).
5. Backend validates the cookie, issues a service ticket, 302 to JumpServer at \`/core/auth/cas/login/?ticket=ST-xxx\`.
6. JumpServer's backend calls \`/p3/serviceValidate\` → receives \`cas:user\` plus attributes → auto-creates the local user (\`source = CAS\`) → signs the user in.

Success criterion: the user-detail page in JumpServer shows **source = CAS** (not Local).`,
      },
      {
        title: '6. Role / group mapping notes',
        body: `**JumpServer system_roles (System Admin / User / Auditor) cannot be auto-mapped via CAS.** The CAS protocol has no role spec, and JumpServer's UI does not expose a role mapping field.

Workable approaches:
1. **Manual** — admin assigns roles in the JumpServer UI. Fine for < 100-user demos / small teams.
2. **User groups** — add \`attribute_mapping: {groups: groups}\` to the MXID protocol_config, then patch \`apps/authentication/backends/cas/views.py\` with a signal that syncs the CAS \`groups\` attribute into JumpServer user groups. High maintenance overhead.
3. **EE OIDC** — JumpServer EE's OIDC integration supports \`role_attribute_path\`, which can map roles out of a \`groups\` claim.

**If the user already exists, SSO will not overwrite attributes**: JumpServer pairs the CAS principal against the local username and signs the user in as that local account. It does not update email / name. To test attribute sync, sign in as a **new** user (one that does not yet exist locally) so JumpServer auto-creates it from the CAS payload.`,
      },
      {
        title: '7. EE OIDC alternative',
        body: `**JumpServer EE License only.** Switch MXID to an OIDC app; the redirect URI is:

\`\`\`
http://<jumpserver>/core/auth/oidc/callback/
\`\`\`

JumpServer System settings → Authentication → OIDC:

\`\`\`
Base site URL            http://<jumpserver>
Provider Endpoint        {{ISSUER}}/protocol/oidc
Client ID                <MXID app.client_id>
Client Secret            <MXID app.client_secret>
Scopes                   openid profile email
\`\`\`

JumpServer fetches \`{{ISSUER}}/protocol/oidc/.well-known/openid-configuration\` automatically.`,
      },
    ],
    notes: [
      '⚠️ Override the platform default subject_strategy (persistent_id) to username on every new CAS app — otherwise cas:user is a numeric ID.',
      '⚠️ The MXID server URL MUST end with a slash because of django-cas-ng urljoin behavior.',
      '⚠️ The JumpServer "callback URL" is the root URL only (no path) — it is CAS_ROOT_PROXIED_AS, not a real callback path.',
      'v4 requires the DOMAINS env var; without it the login page errors out.',
      'service_urls=[] allows any service URL. A strict allow-list HasPrefix-matches the full URL (including query string).',
      'CAS 1.0 / 2.0 / 3.0 are all supported; clients default to 3.0 (p3/serviceValidate) for attributes.',
      'Community CAS does not support single logout — JumpServer logout does not propagate back to MXID.',
      'system_roles cannot be auto-mapped via CAS; assign manually, upgrade to EE OIDC, or write a signal hook.',
    ],
  },

  /* ─────────────── Harbor ─────────────── */
  {
    slug: 'harbor-oidc',
    app: 'Harbor',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['Container', 'Image registry', 'OIDC'],
    summary: 'Harbor v2.x ships native OIDC; project membership is auto-created per group.',
    steps: [
      {
        title: '1. MXID app',
        body: `Protocol OIDC / code \`harbor\` / Redirect URI \`https://<harbor>/c/oidc/callback\`.

**Required**: add a claim mapper that pushes \`groups\` into the userinfo response:

\`\`\`json
{
  "claim_mappers": [
    {"claim": "groups", "source": "user.groups.codes"},
    {"claim": "email",  "source": "user.email"},
    {"claim": "name",   "source": "user.display_name"}
  ]
}
\`\`\`

${FALLBACK_BODY}`,
      },
    ],
    notes: [
      'Harbor maps OIDC groups to projects 1:1 by name.',
      'Without claim_mapper for groups, every SSO user is created without any project.',
    ],
  },

  /* ─────────────── Grafana (verified) ─────────────── */
  {
    slug: 'grafana-oidc',
    app: 'Grafana',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['Monitoring', 'Observability', 'OIDC', 'Verified'],
    summary: 'Grafana generic_oauth provider — 5-minute verified integration.',
    steps: [
      {
        title: '1. MXID app',
        body: `Apps → New app:

- Protocol: **OIDC**
- Code: \`grafana\` or autogenerated (Grafana does not use the code in routing)
- Name: Grafana
- Client type: **web_app** (confidential, uses client_secret)
- subject_strategy: \`username\`
- Redirect URI: \`http://<grafana>/login/generic_oauth\` (in a docker scenario, this is the browser-facing URL, e.g. \`http://localhost:4000/login/generic_oauth\`).

Access policy: add at least an \`allow public\` rule or \`allow group=grafana-users\`.

**Protocol config — key: add the claim_mapper to push groups into userinfo**:

\`\`\`json
{
  "claim_mappers": [
    {"claim": "groups", "source": "user.groups.codes"}
  ]
}
\`\`\`

Without this, userinfo has no \`groups\` array, Grafana's \`role_attribute_path\` cannot find a group list, and the user always falls back to Viewer.`,
      },
      {
        title: '2. Grafana configuration (env or grafana.ini)',
        body: `**Docker compose env form** (recommended, equivalent to grafana.ini):

\`\`\`yaml
environment:
  GF_AUTH_GENERIC_OAUTH_ENABLED: "true"
  GF_AUTH_GENERIC_OAUTH_NAME: "MXID"
  GF_AUTH_GENERIC_OAUTH_CLIENT_ID: "<client_id>"
  GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: "<client_secret>"
  GF_AUTH_GENERIC_OAUTH_SCOPES: "openid profile email"
  GF_AUTH_GENERIC_OAUTH_USE_PKCE: "true"
  # Browser-facing — must be reachable from the user's machine.
  GF_AUTH_GENERIC_OAUTH_AUTH_URL: "{{ISSUER}}/protocol/oidc/authorize"
  # Server-to-server — must be reachable from inside the Grafana container.
  GF_AUTH_GENERIC_OAUTH_TOKEN_URL: "http://host.docker.internal:10050/protocol/oidc/token"
  GF_AUTH_GENERIC_OAUTH_API_URL: "http://host.docker.internal:10050/protocol/oidc/userinfo"
  GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP: "true"
  GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: "contains(groups[*], 'grafana-admins') && 'Admin' || 'Viewer'"
extra_hosts:
  - "host.docker.internal:host-gateway"
\`\`\`

⚠️ **auth_url uses \`localhost\` (browser-facing), token_url / api_url use \`host.docker.internal\` (container-facing).** auth_url is a 302 that the browser follows — it must resolve from the user's machine. token_url / api_url are HTTP requests made by the Grafana container, where \`localhost\` would mean Grafana itself; \`host.docker.internal\` reaches the host's MXID backend.`,
      },
      {
        title: '3. Verification',
        body: `1. Open Grafana's login page in an incognito window.
2. Click **Sign in with MXID** → bounce to the MXID OIDC authorize endpoint → enter credentials.
3. Consent (if \`require_consent\` is on) → back to Grafana at \`/login/generic_oauth\`.
4. Grafana's backend calls \`/oidc/token\` + \`/oidc/userinfo\` → reads \`sub\` + \`groups\` → auto-provisions the user → computes the role via \`role_attribute_path\`.
5. Land in the dashboard. Grafana \`Server Admin → Users\` shows the new user with login type \`OAuth\`.`,
      },
    ],
    notes: [
      '⚠️ The MXID app must include the claim_mapper {claim:"groups", source:"user.groups.codes"}, otherwise Grafana never sees groups and everyone is Viewer.',
      '⚠️ In docker, auth_url=localhost, token/api=host.docker.internal (on Linux add extra_hosts: host-gateway).',
      'role_attribute_path is JMESPath; contains(groups[*], "x") matches a group code.',
      'For JIT-aware roles, point role_attribute_path at `app_roles` instead of `groups` (e.g. `app_roles[0] == \'admin\' && \'Admin\' || \'Viewer\'`). The JIT-elevated app role sits first in app_roles, so Grafana promotes to Admin for the grant window and drops back when it expires — no claim_mapper needed.',
      'ALLOW_SIGN_UP=true is required for Grafana to auto-create users on SSO. If false, users must already exist locally.',
      'subject_strategy=username is sufficient — Grafana uses sub as the unique identifier.',
    ],
  },

  /* ─────────────── Gitea ─────────────── */
  {
    slug: 'gitea-oidc',
    app: 'Gitea',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['Git', 'Code hosting', 'OIDC'],
    summary: 'Gitea OAuth2 Source — the most common SSO integration in self-hosted Git.',
    steps: [
      {
        title: '1. MXID app',
        body: `Protocol OIDC / code \`gitea\` / Redirect URI \`https://<gitea>/user/oauth2/MXID/callback\`.

${FALLBACK_BODY}`,
      },
      {
        title: '2. Gitea admin',
        body: `Site Administration → Authentication Sources → Add:

\`\`\`
Type:              OAuth2
Auth Name:         MXID            ← must match the name in the callback URL
OAuth2 Provider:   OpenID Connect
Client ID:         <client_id>
Client Secret:     <client_secret>
OpenID Connect Auto Discovery URL:
   {{ISSUER}}/protocol/oidc/.well-known/openid-configuration
\`\`\``,
      },
    ],
    notes: [
      'The auth-source name and the callback URL slug must match exactly.',
    ],
  },

  /* ─────────────── Atlassian (Jira / Confluence) ─────────────── */
  {
    slug: 'jira-saml',
    app: 'Jira (Cloud / Data Center)',
    protocol: 'saml',
    difficulty: 2,
    tags: ['Atlassian', 'Collab', 'SAML'],
    summary: 'Atlassian standardises on SAML 2.0; the SAML NameID must be the email.',
    steps: [
      {
        title: 'Outline',
        body: `1. Create a SAML app in MXID with code \`jira\`. Subject strategy = \`email\`.
2. Download IdP metadata from \`{{ISSUER}}/protocol/saml/jira/metadata\`.
3. Atlassian Admin → Security → SAML SSO → upload the metadata, set the ACS URL to \`https://<jira>/plugins/servlet/samlconsumer\`.
4. Map the NameID to user email; map FirstName / LastName attributes.

${FALLBACK_BODY}`,
      },
    ],
    notes: [
      'Atlassian rejects SAML responses where NameID is not the user email.',
      'Atlassian Cloud requires an Atlassian Access subscription for SAML.',
    ],
  },
  {
    slug: 'confluence-saml',
    app: 'Confluence',
    protocol: 'saml',
    difficulty: 2,
    tags: ['Atlassian', 'Collab', 'SAML'],
    summary: 'Identical to Jira; just swap the ACS URL.',
    steps: [
      {
        title: 'ACS URL only',
        body: `Reuse the Jira SAML guide. Replace the ACS URL with:

\`\`\`
https://<confluence>/plugins/servlet/samlconsumer
\`\`\`

${FALLBACK_BODY}`,
      },
    ],
  },

  /* ─────────────── AWS ─────────────── */
  {
    slug: 'aws-saml',
    app: 'AWS Console',
    protocol: 'saml',
    difficulty: 3,
    tags: ['AWS', 'Cloud', 'SAML'],
    summary: 'AWS Identity Provider + IAM Role mapping. IAM role is assigned per group.',
    steps: [
      {
        title: 'Outline',
        body: `1. AWS Console → IAM → Identity Providers → Add. Upload \`{{ISSUER}}/protocol/saml/aws/metadata\`.
2. Create IAM roles trusting that IdP.
3. Add a SAML attribute mapper in MXID emitting \`https://aws.amazon.com/SAML/Attributes/Role\` with the value \`<role_arn>,<idp_arn>\`.
4. SP-initiated login at \`https://signin.aws.amazon.com/saml\`.

${FALLBACK_BODY}`,
      },
    ],
    notes: [
      'The Role attribute value format is strict: <role_arn>,<idp_arn> joined by a comma.',
      'AWS picks the role from the Role attribute when there is exactly one — otherwise it shows a role picker.',
    ],
  },

  /* ─────────────── Jenkins ─────────────── */
  {
    slug: 'jenkins-cas',
    app: 'Jenkins',
    protocol: 'cas',
    difficulty: 2,
    tags: ['CI/CD', 'CAS'],
    summary: 'Jenkins CAS Plugin — old but rock-solid.',
    steps: [
      {
        title: 'Outline',
        body: `1. Install the CAS Plugin in Jenkins.
2. Manage Jenkins → Configure Global Security → Security Realm → CAS.
3. Server URL: \`{{ISSUER}}/protocol/cas/jenkins/\` (trailing slash required, same as JumpServer).
4. CAS 3.0 protocol. Username attribute: \`username\`.

${FALLBACK_BODY}`,
      },
    ],
    notes: [
      'Jenkins CAS plugin defaults to CAS 1.0. Pick CAS 3.0 if you want attributes (email / display name).',
    ],
  },

  /* ─────────────── Lark / Feishu (login MXID itself) ─────────────── */
  {
    slug: 'lark-login',
    app: 'Lark / Feishu → MXID',
    protocol: 'oidc',
    difficulty: 2,
    tags: ['External IdP', 'Lark', 'Feishu'],
    summary: 'Use Lark / Feishu as an external login source for MXID. Console → Identity sources.',
    steps: [
      {
        title: 'Outline',
        body: `1. Lark Developer Console → create an internal app → enable the "Get user info" + "Get user identity" scopes.
2. Copy App ID + App Secret.
3. MXID Console → Identity sources → New → Lark / Feishu. Paste the credentials, set the redirect URI to \`{{ISSUER}}/api/v1/portal-public/auth/external/lark/callback\`.
4. Save. The Lark button appears on the portal login page automatically.

${FALLBACK_BODY}`,
      },
    ],
    notes: [
      'External-IdP users are bound to local accounts by email on first login.',
      'Subsequent logins reuse the binding silently.',
    ],
  },
]
