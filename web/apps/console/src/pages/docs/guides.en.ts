// Integration guides — English content. Mirrors guides.zh.ts slug-by-slug,
// step-by-step. Both files satisfy the same `Guide[]` type from ./types.ts.
//
// The page (index.tsx) renders this list when i18n.language is not zh-*.
//
// Content policy: every endpoint path, claim name and default value here is
// checked against internal/protocol/* and docs/integrations/README.md. If you
// change protocol behaviour in the backend, update BOTH language files.

import type { Guide } from './types'

export const GUIDES: Guide[] = [
  /* ─────────────── Deploy / Ops ─────────────── */
  {
    slug: 'prod-deploy',
    app: 'Production deployment',
    protocol: 'deploy',
    difficulty: 2,
    tags: ['Deploy', 'nginx', 'Single domain', 'TLS'],
    summary:
      'MXID recommends single-domain path routing: one HTTPS domain serves portal + console + API + protocol endpoints.',
    steps: [
      {
        title: '1. Plan the domain',
        body: `**Single-domain model** (right for ~80% of deployments):

\`\`\`
https://id.example.com/             ← portal SPA (end-user login)
https://id.example.com/admin/       ← console SPA (administration)
https://id.example.com/api/         ← REST API
https://id.example.com/protocol/    ← OIDC / SAML / CAS endpoints
\`\`\`

issuer = portal_url = the same origin. Both the OIDC \`iss\` claim and the SAML EntityID are derived from it.

**Hard constraint**: \`issuer_url\` **must** be the exact origin your users see in the browser. If it differs, relying parties will reject the \`iss\` claim and SAML SPs will reject the assertion issuer.`,
      },
      {
        title: '2. Backend config.prod.yaml',
        body: `\`\`\`yaml
server:
  port: 8080
  mode: release
  issuer_url:  "https://id.example.com"
  portal_url:  "https://id.example.com"
  console_url: "https://id.example.com/admin"

session:
  cookie_secure: true        # required once you are on https
  cookie_domain: "id.example.com"

crypto:
  # 32-byte AES-256 master key — always inject via env, never commit it
  # export MXID_CRYPTO_KEY_ENCRYPTION_KEY=<base64>
  key_encryption_key: ""
\`\`\`

Also set \`trusted_proxies\` to your load balancer / ingress CIDRs. Without it every request appears to come from the LB's single IP, so all users share one rate-limit bucket and the whole office gets 429'd together.`,
      },
      {
        title: '3. nginx reverse proxy',
        body: `\`\`\`nginx
server {
  listen 443 ssl http2;
  server_name id.example.com;

  ssl_certificate     /etc/letsencrypt/live/id.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/id.example.com/privkey.pem;

  # —— Portal SPA build (end-user login) ——
  root /var/www/mxid/portal;
  index index.html;
  location / {
    try_files $uri /index.html;
  }

  # —— Console SPA build (administration) ——
  location /admin/ {
    alias /var/www/mxid/console/;
    try_files $uri $uri/ /admin/index.html;
  }

  # —— Backend (API + protocol endpoints) ——
  location ~ ^/(api|protocol|openapi)/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 60s;
  }
}

# HTTP → HTTPS redirect
server {
  listen 80;
  server_name id.example.com;
  return 301 https://$host$request_uri;
}
\`\`\`

⚠️ **The \`X-Forwarded-Proto\` line is not optional, and it must be repeated inside every \`location\` block that proxies.** nginx drops *all* inherited \`proxy_set_header\` directives the moment you set *any* \`proxy_set_header\` inside a location. Lose that header and the OIDC engine sees \`scheme=http\`, compares it against your \`https\` issuer, and rejects discovery / authorize with **403**.`,
      },
      {
        title: '4. Build the frontends',
        body: `\`\`\`bash
# Portal
cd web/apps/portal
pnpm build
# emits dist/ → copy to /var/www/mxid/portal/

# Console
cd web/apps/console
pnpm build
# emits dist/ → copy to /var/www/mxid/console/
\`\`\`

**Console base path**: because the console is served from \`/admin/\`, set \`base: '/admin/'\` in \`vite.config.ts\` before building — otherwise every hashed asset 404s.`,
      },
      {
        title: '5. Two-domain variant (optional)',
        body: `If the console has to live on its own hostname (internal network / VPN only):

\`\`\`yaml
server:
  issuer_url:  "https://id.example.com"
  portal_url:  "https://id.example.com"
  console_url: "https://admin-id.example.com"
\`\`\`

Give \`admin-id.example.com\` its own nginx server block with \`root\` pointed at the console build; you can then add an IP allow-list or mTLS in front of it. The issuer and portal origins stay unchanged.

**Caveat**: cookies are not shared across origins — console and portal each require their own login. The session cookie is currently bound to the \`portal_url\` domain, so **a two-domain deployment needs a cross-origin token bridge that does not exist yet**. Prefer the single-domain layout unless you have a hard requirement.`,
      },
      {
        title: '6. Verification checklist',
        body: `\`\`\`
✓  https://id.example.com/                       portal login page
✓  https://id.example.com/admin/                 console
✓  https://id.example.com/api/v1/system/info     returns the right URLs
✓  https://id.example.com/health                 backend liveness
✓  OIDC discovery (global):
    https://id.example.com/protocol/oidc/.well-known/openid-configuration
✓  SAML metadata (per app):
    https://id.example.com/protocol/saml/<app_code>/metadata
✓  CAS login (per app):
    https://id.example.com/protocol/cas/<app_code>/login?service=...
\`\`\`

\`system/info\` should return:
\`\`\`json
{
  "issuer_url":  "https://id.example.com",
  "portal_url":  "https://id.example.com",
  "console_url": "https://id.example.com/admin"
}
\`\`\`

Sanity-check the proxy header from the outside before wiring up your first app:
\`\`\`bash
curl -s https://id.example.com/protocol/oidc/.well-known/openid-configuration | head -c 120
# expected: {"issuer":"https://id.example.com/protocol/oidc","authorization_endpoint":...
# a 403, or an HTML document, means X-Forwarded-Proto is not reaching the backend
\`\`\``,
      },
    ],
    notes: [
      'Inject crypto.key_encryption_key from the environment — never commit it to a YAML file in the repo.',
      'Once cookie_secure=true the deployment must be HTTPS end-to-end; over plain HTTP the browser silently drops the cookie and every login fails.',
      'The proxy must forward X-Forwarded-Proto, otherwise the OIDC engine 403s on scheme mismatch and callback URLs are generated as http. On Kubernetes this is the helm value routing.forwardedProtoHttps (HTTPRoute / VirtualService header filter).',
      'Set trusted_proxies (helm: config.trustedProxies) or every client collapses into the LB IP and shares one rate-limit bucket → cluster-wide 429s.',
      'After changing the console base path, hard-refresh the browser — cached index.html still points at the old /assets/ paths.',
    ],
  },

  /* ─────────────── Protocol references ─────────────── */
  {
    slug: 'oidc-protocol-reference',
    app: 'OIDC protocol reference',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['Protocol', 'Reference', 'OpenID Connect'],
    summary:
      'MXID implements OpenID Connect Core 1.0 + Discovery 1.0 on zitadel/oidc v3. Endpoints are global; apps are distinguished by client_id.',
    steps: [
      {
        title: '1. Endpoint overview',
        body: `OIDC endpoints are **global** in MXID (no \`app_code\` segment). Every app shares the same set of URLs and is identified by its \`client_id\`.

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
\`\`\`

Note the \`iss\` value carries the \`/protocol/oidc\` suffix — it is **not** the bare host. When a client asks for "the issuer" or "the provider endpoint", give it \`{{ISSUER}}/protocol/oidc\`.

**Whenever the client supports it, paste the Discovery URL instead of filling endpoints by hand.** Most integrations need nothing beyond discovery URL + client_id + client_secret.`,
      },
      {
        title: '2. Deployment prerequisite — read this before the first app',
        body: `When MXID sits behind a TLS-terminating edge (nginx, cloud LB, GKE Gateway, Istio), TLS is stripped before the request reaches the backend. The OIDC engine then sees \`scheme=http\`, compares it against the \`https\` issuer, and **rejects discovery and authorize with HTTP 403**.

**You must forward \`X-Forwarded-Proto: https\` to the backend.**

- **Helm**: \`routing.forwardedProtoHttps: true\` (default). It injects the header via the HTTPRoute filter (Gateway API) or the VirtualService header block (Istio). Most Ingress controllers set it themselves.
- **nginx**: declare it explicitly inside \`location /protocol/\`:
  \`\`\`nginx
  proxy_set_header X-Forwarded-Proto $scheme;
  \`\`\`
  Repeat it in *every* location that proxies — as soon as a location sets any \`proxy_set_header\`, all inherited ones are discarded.

Symptoms of a missing header:

\`\`\`
Discovery URL returns 403
Client reports: ParseException: Unexpected token <!doctype html>
   (the 403 fell through to the SPA's index.html)
\`\`\`

Quick test — if adding the header by hand makes it work, this is your bug:
\`\`\`bash
curl -s -H "X-Forwarded-Proto: https" {{ISSUER}}/protocol/oidc/.well-known/openid-configuration | head -c 120
\`\`\`

Also configure \`trusted_proxies\` (helm: \`config.trustedProxies\`). Without it every client's real IP collapses into the LB's IP and they all share one rate-limit bucket — an entire office gets 429'd at once.`,
      },
      {
        title: '3. Discovery document (OIDC Discovery 1.0)',
        body: `The first step of any OIDC integration is fetching this JSON:

\`\`\`bash
curl {{ISSUER}}/protocol/oidc/.well-known/openid-configuration
\`\`\`

Key fields:

\`\`\`json
{
  "issuer": "{{ISSUER}}/protocol/oidc",
  "authorization_endpoint": "{{ISSUER}}/protocol/oidc/authorize",
  "token_endpoint": "{{ISSUER}}/protocol/oidc/token",
  "userinfo_endpoint": "{{ISSUER}}/protocol/oidc/userinfo",
  "jwks_uri": "{{ISSUER}}/protocol/oidc/jwks",
  "end_session_endpoint": "{{ISSUER}}/protocol/oidc/end-session",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
  "code_challenge_methods_supported": ["S256"],
  "backchannel_logout_supported": true,
  "scopes_supported": ["openid", "profile", "email", "phone", "address", "groups", "offline_access"]
}
\`\`\`

**Capability matrix of the current engine:**

| Item | Support |
|------|---------|
| \`response_type\` | **\`code\` only** (authorization code + PKCE S256). Implicit and hybrid were removed in v1.2.0 per OAuth 2.1. |
| \`grant_type\` | \`authorization_code\`, \`refresh_token\`, \`client_credentials\` (machine-to-machine) |
| Client authentication | \`client_secret_basic\`, \`client_secret_post\`, \`private_key_jwt\`, \`none\` (public client + PKCE) |
| **Not supported** | \`client_secret_jwt\` (HS256) — secrets are stored one-way bcrypt-hashed, so the server cannot compute the HMAC. Use \`private_key_jwt\`. |
| Refresh token | Only issued when the client requests the **\`offline_access\`** scope |
| Back-channel logout | Supported — offboarding and JIT expiry force downstream apps to log out |

If a client is hard-wired to implicit or hybrid ("id_token" / "code id_token"), it cannot integrate as-is; switch it to the code flow.`,
      },
      {
        title: '4. JWKS (signing public keys)',
        body: `RPs fetch the public key from here to verify the \`id_token\` signature:

\`\`\`bash
curl {{ISSUER}}/protocol/oidc/jwks
\`\`\`

Returns a standard JWK Set. MXID signs with RS256; keys rotate per tenant and the \`kid\` header of the token selects the matching JWK. Clients should re-fetch JWKS on an unknown \`kid\` rather than caching it forever.`,
      },
      {
        title: '5. Authorize request (code flow + PKCE)',
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

- \`code_challenge_method=plain\` is **not supported** (OAuth 2.1 BCP mandates S256).
- Public clients (SPA / mobile) leave \`client_secret\` empty and rely on PKCE alone — set the client's auth mode to \`none\`.
- Add \`offline_access\` to \`scope\` if the app needs a refresh token.

**Login confirmation behaviour:**
- **SP-initiated** (the app redirected the user here): the user sees a one-time "Sign in to App X?" confirmation page, Google style. This is expected, not a misconfiguration.
- **IdP-initiated** (the user clicked the app tile in the MXID portal): no confirmation, straight through.`,
      },
      {
        title: '6. Token exchange',
        body: `\`\`\`bash
curl -X POST {{ISSUER}}/protocol/oidc/token \\
  -d "grant_type=authorization_code" \\
  -d "code=<from_callback>" \\
  -d "redirect_uri=<same_as_authorize>" \\
  -d "client_id=<id>" \\
  -d "client_secret=<secret>" \\
  -d "code_verifier=<original_verifier>"
\`\`\`

Returns \`access_token\`, \`id_token\` (a signed JWT), \`expires_in\` and \`token_type=Bearer\`. A \`refresh_token\` is included **only if the authorize request asked for \`offline_access\`** — this is the single most common "why do I not get a refresh token" cause.

The \`access_token\` is an **opaque bearer token**, not a JWT. Do not try to parse it locally; resource servers validate it through \`/introspect\` (RFC 7662). This is deliberate — an opaque token can be revoked immediately, whereas a self-contained JWT stays valid until it expires.`,
      },
      {
        title: '7. Standard claims (id_token / userinfo)',
        body: `\`\`\`json
{
  "sub": "kerbos",
  "preferred_username": "kerbos",
  "email": "kerbos@example.com",
  "email_verified": true,
  "name": "Kerbos",
  "tenant_code": "matrixplus",
  "sid": "<session id>",
  "amr": ["pwd", "mfa"],
  "iss": "{{ISSUER}}/protocol/oidc",
  "aud": "<client_id>",
  "iat": 1733678400,
  "exp": 1733679300
}
\`\`\`

- \`sub\` — subject identifier, shaped by the app's **subject strategy**: \`username\` (default), \`username_suffixed\` (\`kerbos@matrixplus\`), \`email\`, \`persistent_id\` (numeric internal ID) or \`pairwise\` (per-client opaque hash). The same person therefore gets a different \`sub\` in different apps under \`pairwise\`.
- \`sid\` — session ID; the back-channel \`logout_token\` carries the same value, so an RP can match the session to terminate.
- \`groups\` — the user's group codes. **Not emitted by default.** Add a claim mapper in the app's protocol config:
  \`\`\`json
  {"claim_mappers": [{"claim": "groups", "source": "user.groups.codes"}]}
  \`\`\`
- \`tenant_code\` — always injected. Shared (cross-tenant) apps should read it to disambiguate users.`,
      },
      {
        title: '8. Roles (the app_roles claim)',
        body: `The user's **effective role codes for this app** are injected into both the id_token and userinfo as \`app_roles\`, a string array:

\`\`\`json
{ "sub": "kerbos", "app_roles": ["admin", "dev"] }
\`\`\`

- **A JIT-elevated role is always first** (\`app_roles[0]\`). An SP that wants a single primary role (Grafana's \`role_attribute_path\`, for example) can read \`app_roles[0]\` and automatically pick up the elevated role; an SP that unions permissions (Jenkins matrix auth) iterates the whole array.
- When the JIT grant expires, the role disappears from \`app_roles\` on the next token — no manual cleanup.
- With no role bindings at all, the app's default role is used.
- No claim mapper is required — \`app_roles\` is always present when the user has at least one role.

SP-side example (Grafana generic_oauth):
\`\`\`
role_attribute_path: app_roles[0] == 'admin' && 'Admin' || 'Viewer'
\`\`\`

Compared to parsing \`groups\`, \`app_roles\` is already scoped to this one app, so you do not have to prefix group codes per application.`,
      },
      {
        title: '9. End Session (RP-Initiated Logout)',
        body: `\`\`\`
GET {{ISSUER}}/protocol/oidc/end-session?
    id_token_hint=<id_token>
    &post_logout_redirect_uri=<your_app_url>
    &state=<optional>
\`\`\`

MXID destroys the user's session and redirects to \`post_logout_redirect_uri\` (which must be registered on the app as its logout URL).

The reverse direction also works: **back-channel logout**. When a user is offboarded, or when a JIT grant expires, MXID POSTs a \`logout_token\` to every RP that registered a back-channel logout URI, so downstream sessions are terminated without the user's browser being involved. Logging out of the MXID portal or console also fans single-logout out to every SP the user still holds a session with.`,
      },
    ],
    notes: [
      'access_token is an opaque bearer token (validate via /introspect); id_token is an RS256-signed JWT. Do not parse the access token.',
      'Defaults: access_token 15m (900s), refresh_token 7d (604800s), id_token 1h. Both token TTLs are overridable per app in the protocol-info tab (protocol_config.access_token_ttl / refresh_token_ttl).',
      'A refresh token requires the offline_access scope. Without it the token response simply has no refresh_token.',
      'client_secret_jwt is not supported — secrets are bcrypt-hashed so the server cannot recompute an HMAC. Use private_key_jwt for JWT client authentication.',
      'response_type is code only. Implicit and hybrid were removed in v1.2.0 (OAuth 2.1); an app record still carrying "id_token" in protocol_config cannot re-enable them.',
      'The same user may get a different sub per app: subject_strategy=pairwise hashes per client_id.',
      'Behind a TLS-terminating proxy you MUST forward X-Forwarded-Proto: https, or the engine 403s the entire OIDC surface.',
    ],
  },
  {
    slug: 'saml-protocol-reference',
    app: 'SAML protocol reference',
    protocol: 'saml',
    difficulty: 2,
    tags: ['Protocol', 'Reference', 'SAML 2.0'],
    summary:
      'MXID implements the SAML 2.0 Web Browser SSO Profile. Each SAML app gets its own endpoint set (per app_code).',
    steps: [
      {
        title: '1. Endpoint overview',
        body: `SAML endpoints are **partitioned by app_code** — every app has its own metadata / SSO / SLO URLs.

\`\`\`
IdP Metadata          {{ISSUER}}/protocol/saml/<app_code>/metadata      GET
SSO Redirect          {{ISSUER}}/protocol/saml/<app_code>/sso           GET  (HTTP-Redirect binding)
SSO POST              {{ISSUER}}/protocol/saml/<app_code>/sso           POST (HTTP-POST binding)
SLO                   {{ISSUER}}/protocol/saml/<app_code>/slo           GET / POST
\`\`\`

Replace \`<app_code>\` with the code you entered when creating the app in the console — e.g. \`jira\`, \`confluence\`, \`aws\`. A bare \`/protocol/saml/metadata\` without the app segment always 404s.`,
      },
      {
        title: '2. IdP metadata',
        body: `Every SAML SP needs the IdP metadata XML:

\`\`\`bash
curl {{ISSUER}}/protocol/saml/jira/metadata
\`\`\`

The XML contains:
- \`<EntityDescriptor entityID="{{ISSUER}}">\` — the **IdP EntityID is the issuer origin itself**, without the \`/protocol/saml/...\` suffix, and it is the same value for every SAML app. Only the SSO/SLO locations differ per app.
- \`<KeyDescriptor use="signing">\` — the signing certificate
- \`<SingleSignOnService>\` — Redirect + POST bindings
- \`<SingleLogoutService>\`
- \`<NameIDFormat>\` list (emailAddress / persistent / transient / unspecified)

**Two ways to hand it over:**
1. **Metadata URL** (preferred): give the SP \`{{ISSUER}}/protocol/saml/jira/metadata\` and it will re-fetch on a schedule, picking up certificate rotation automatically.
2. **Metadata XML**: open the URL in a browser, save the file, upload it in the SP.

The signing certificate is minted lazily on first use, so the metadata endpoint always returns a usable document even for a freshly created app.`,
      },
      {
        title: '3. What the SP administrator needs',
        body: `Checklist to hand over:

\`\`\`
IdP Entity ID:        {{ISSUER}}
SSO URL (Redirect):   {{ISSUER}}/protocol/saml/<app_code>/sso
SSO URL (POST):       {{ISSUER}}/protocol/saml/<app_code>/sso
SLO URL:              {{ISSUER}}/protocol/saml/<app_code>/slo
X.509 Cert:           copy from <ds:X509Certificate> in the metadata
NameID Format:        urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress (recommended)
Signature Algorithm:  RSA-SHA256 (digest SHA-256)
\`\`\`

On the MXID side, fill in the app's \`protocol_config\`:
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
\`\`\`

\`acs_url\` and \`sp_entity_id\` are mandatory — they come from the SP's own metadata. \`session_ttl\` (seconds, default 28800 = 8h) is the SessionNotOnOrAfter written into the assertion.`,
      },
      {
        title: '4. Default attribute output',
        body: `Attribute \`Name\`s come from \`attribute_mapping\`. **Defaults**: \`username→uid\`, \`email→mail\`, \`display_name→displayName\`, \`phone→telephoneNumber\`. In addition, \`username\` (the raw value) and \`tenant_code\` are always injected. With the default config the assertion looks like:

\`\`\`xml
<saml:AttributeStatement>
  <saml:Attribute Name="uid">
    <saml:AttributeValue>kerbos</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="mail">
    <saml:AttributeValue>kerbos@example.com</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="displayName">
    <saml:AttributeValue>Kerbos</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="username">
    <saml:AttributeValue>kerbos</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="tenant_code">
    <saml:AttributeValue>matrixplus</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
\`\`\`

To rename an attribute, change \`attribute_mapping\`. If the SP expects \`email\` rather than \`mail\`, set \`{"email": "email"}\`.

Only these five user fields can be mapped: \`username\`, \`email\`, \`display_name\`, \`phone\`, \`avatar\`. There is **no constant/static attribute mapper** — you cannot emit a fixed literal value this way.`,
      },
      {
        title: '5. Roles and groups (multi-value attributes)',
        body: `**Roles.** The user's effective role codes for this app are emitted as a single **multi-value attribute**, named by \`role_attribute\` (default \`roles\`; set it to whatever the SP expects — \`memberOf\`, \`groups\`, \`Role\`):

\`\`\`xml
<saml:Attribute Name="roles">
  <saml:AttributeValue>admin</saml:AttributeValue>
  <saml:AttributeValue>dev</saml:AttributeValue>
</saml:Attribute>
\`\`\`

- **A JIT-elevated role comes first** (the first \`AttributeValue\`).
- When the grant expires, the role disappears on the next assertion.
- Map SP permissions off this attribute — e.g. the Jenkins SAML plugin's *Group Attribute*.

**Groups (since v1.7.0).** Group codes are a separate, **opt-in** multi-value attribute controlled by \`group_attribute\`. Leave it empty (the default) and groups are not sent at all; set a name to enable them:

\`\`\`json
{
  "role_attribute": "memberOf",
  "group_attribute": "groups"
}
\`\`\`

Roles and groups are independent, so an SP can receive both. Point them at the same attribute name only if you deliberately want them merged.`,
      },
      {
        title: '6. SLO (Single Logout)',
        body: `Two directions:

**IdP-initiated** — the user logs out of the MXID portal, and MXID pushes a LogoutRequest to every SP the user still has a session with (tracked in a per-user session index).

**SP-initiated** — the SP sends a LogoutRequest to \`{{ISSUER}}/protocol/saml/<app_code>/slo\`; MXID clears the session and replies with a LogoutResponse.

Fan-out is best-effort and non-blocking: MXID does not fail your logout because one SP is unreachable. SLO only works as well as the SP implements it — several commercial SaaS products (Jira Cloud among them) do not support it at all.`,
      },
      {
        title: '7. Verify the metadata',
        body: `After deployment, open this in a browser — you should get XML:

\`\`\`
{{ISSUER}}/protocol/saml/<app_code>/metadata
\`\`\`

\`404 application not found\` means the app_code does not exist, or the app's protocol is not SAML.

If the response is a 500 mentioning a non-absolute issuer, the external URL is unconfigured — MXID fails loudly here rather than baking a broken relative URL into metadata that no SP can consume.`,
      },
    ],
    notes: [
      'Assertions and responses are signed by default (RSA-SHA256 / SHA-256 digest). Assertion encryption is off by default — HTTPS is the transport guarantee.',
      'The IdP EntityID is the issuer origin ({{ISSUER}}), identical for every SAML app; only the SSO/SLO locations are per-app.',
      'Whether MXID must verify a signed AuthnRequest depends on the SP: upload the SP certificate as sp_cert if the SP signs its requests.',
      'NameID shape is driven by the app subject strategy (email / persistent_id / username / username_suffixed / pairwise), not by name_id_format alone.',
      'attribute_mapping only covers username / email / display_name / phone / avatar. There is no static-literal attribute mapper.',
      'Roles always ship under role_attribute (default `roles`); groups ship only when group_attribute is set (v1.7.0+). JIT-elevated roles come first and drop out when the grant expires.',
    ],
  },
  {
    slug: 'cas-protocol-reference',
    app: 'CAS protocol reference',
    protocol: 'cas',
    difficulty: 2,
    tags: ['Protocol', 'Reference', 'CAS 3.0'],
    summary:
      'MXID implements CAS Protocol 3.0. Ticket validation is simple, which makes it the first choice for legacy Java / Python apps.',
    steps: [
      {
        title: '1. Endpoint overview',
        body: `CAS endpoints are **partitioned by app_code**:

\`\`\`
Login                 {{ISSUER}}/protocol/cas/<app_code>/login              GET
Validate (CAS 1.0)    {{ISSUER}}/protocol/cas/<app_code>/validate           GET
Service Validate      {{ISSUER}}/protocol/cas/<app_code>/serviceValidate    GET   (CAS 2.0, XML)
P3 Service Validate   {{ISSUER}}/protocol/cas/<app_code>/p3/serviceValidate GET   (CAS 3.0, XML + attributes)
Proxy                 {{ISSUER}}/protocol/cas/<app_code>/proxy              GET   (opt-in)
Proxy Validate        {{ISSUER}}/protocol/cas/<app_code>/p3/proxyValidate   GET   (opt-in)
Logout                {{ISSUER}}/protocol/cas/<app_code>/logout             GET
\`\`\`

**Use P3.** Only CAS 3.0 returns attributes in the ServiceResponse; \`serviceValidate\` gives you the username and nothing else.`,
      },
      {
        title: '2. Typical flow',
        body: `1. The user hits a protected resource; the SP redirects to MXID:
\`\`\`
{{ISSUER}}/protocol/cas/<app_code>/login?service=<SP_callback_url>
\`\`\`

2. The user signs in; MXID redirects back to the SP with a ticket appended:
\`\`\`
<SP_callback_url>?ticket=ST-xxxxxxxx
\`\`\`

3. The SP's **backend** validates the ticket out-of-band (this is what makes CAS forgery-resistant — the ticket never has to be trusted from the browser):
\`\`\`
GET {{ISSUER}}/protocol/cas/<app_code>/p3/serviceValidate?
    service=<SP_callback_url>
    &ticket=ST-xxxxxxxx
\`\`\`

4. MXID returns XML with the principal plus attributes.

The \`service\` parameter in step 3 must be byte-identical to the one used in step 1, or validation fails — this is a CAS spec requirement, not an MXID quirk.`,
      },
      {
        title: '3. P3 ServiceValidate response',
        body: `Attribute element names come from \`attribute_mapping\`. **Defaults**: \`username→uid\`, \`email→mail\`, \`display_name→displayName\`, \`phone→telephoneNumber\`; \`tenant_code\` is injected automatically. With the default config:

\`\`\`xml
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>kerbos</cas:user>
    <cas:attributes>
      <cas:uid>kerbos</cas:uid>
      <cas:mail>kerbos@example.com</cas:mail>
      <cas:displayName>Kerbos</cas:displayName>
      <cas:tenant_code>matrixplus</cas:tenant_code>
      <cas:roles>admin</cas:roles>
      <cas:roles>dev</cas:roles>
    </cas:attributes>
  </cas:authenticationSuccess>
</cas:serviceResponse>
\`\`\`

- \`<cas:user>\` is the resolved subject — its shape follows the app's subject strategy, so it is *not* necessarily the login name.
- Beyond the mapped user fields and \`tenant_code\`, the user's **effective role codes** are emitted as a **multi-value attribute** (one element per role). The element name comes from \`role_attribute\` (default \`roles\`; \`memberOf\` / \`groups\` also common). **JIT-elevated roles come first** and disappear when the grant expires.
- Group codes are opt-in via \`group_attribute\` (v1.7.0+); empty means groups are not sent.

Failure response:

\`\`\`xml
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationFailure code="INVALID_TICKET">
    ticket not found or expired
  </cas:authenticationFailure>
</cas:serviceResponse>
\`\`\``,
      },
      {
        title: '4. Ticket lifecycle',
        body: `- **Service Ticket (ST)** \`ST-...\`: single use, valid for 30 seconds between issue and validation by default (tune via \`protocol_config.ticket_ttl\`).
- Consumed on first validation (replay protection).
- Logging in again against the same service mints a new ticket; the old one is not proactively invalidated, it just expires.
- **Proxy tickets** (PGT/PT) are off by default. Set \`proxy_enabled: true\` to allow proxy chains; \`pgt_ticket_ttl\` defaults to 7200s. Each hop widens the attack surface, so this is deliberately fail-closed.

⚠️ **\`service_urls\` is fail-CLOSED.** An empty allow-list rejects *every* login with \`invalid service URL\` — it does **not** mean "allow anything". You must register at least one service URL before CAS login will work for that app. Matching is: scheme + host (case-insensitive, exact, port included) plus a path-prefix match, so one \`https://app.example.com/cas\` entry covers \`/cas\`, \`/cas/\` and \`/cas/foo\`. URLs carrying a userinfo component are rejected outright.`,
      },
      {
        title: '5. What the SP administrator needs',
        body: `\`\`\`
CAS Server URL:       {{ISSUER}}/protocol/cas/<app_code>/
CAS Protocol:         3.0 (enable P3)
Validate URL:         {{ISSUER}}/protocol/cas/<app_code>/p3/serviceValidate
Logout URL:           {{ISSUER}}/protocol/cas/<app_code>/logout
\`\`\`

Note the trailing slash on the server URL — several CAS clients (django-cas-ng among them) join \`login\` onto it with RFC 3986 relative resolution, which drops the last segment when the slash is missing.

MXID-side \`protocol_config\`:
\`\`\`json
{
  "service_urls": ["https://<sp>/cas/callback"],
  "ticket_ttl": 30,
  "role_attribute": "roles",
  "attribute_mapping": {
    "email": "mail",
    "display_name": "cn"
  }
}
\`\`\`

\`service_urls\` must be non-empty — see step 4.`,
      },
      {
        title: '6. Logout',
        body: `\`\`\`
GET {{ISSUER}}/protocol/cas/<app_code>/logout?service=<return_url>
\`\`\`

MXID destroys the session and redirects to \`service\` (which must also be in the allow-list).

MXID additionally implements **CAS back-channel single logout**: it records every service the user authenticated to, and on portal/console logout POSTs a \`logoutRequest\` XML document (carrying the original service ticket in \`<samlp:SessionIndex>\`) to each SP's logout endpoint — \`logout_url\` if configured, otherwise the recorded service URL. Delivery is best-effort and goes through the SSRF-guarded HTTP client.

What CAS does **not** give you is the reverse: an SP-side logout does not notify MXID. The SP has to expire its own session.`,
      },
    ],
    notes: [
      'CAS carries no signature — its security rests entirely on HTTPS plus a strict service-URL allow-list.',
      'service_urls is fail-closed: an empty list rejects every login (invalid service URL). Register the SP callback before testing.',
      'The only difference between p3/serviceValidate and serviceValidate is attributes — always use p3.',
      'Service URL matching is scheme+host exact, path prefix; the classic https://app.com.evil.com bypass does not match.',
      'Roles ship under role_attribute (default `roles`), one element per role, JIT-elevated first. Groups are opt-in via group_attribute (v1.7.0+).',
      'Proxy tickets (PGT/PT) are off unless proxy_enabled is set on the app.',
    ],
  },

  /* ─────────────── JumpServer (verified) ─────────────── */
  {
    slug: 'jumpserver-cas',
    app: 'JumpServer',
    protocol: 'cas',
    difficulty: 2,
    tags: ['Bastion', 'DevOps', 'CAS', 'Community Edition', 'Verified'],
    summary:
      'JumpServer v4 community edition + CAS — end-to-end verified. OIDC / SAML are EE-only on JumpServer; CAS is the safest community-edition path.',
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

**Protocol config**:
\`\`\`json
{
  "service_urls": ["http://<jumpserver>/core/auth/cas/login/"],
  "ticket_ttl": 30,
  "attribute_mapping": {
    "username": "uid",
    "email": "mail",
    "display_name": "displayName",
    "phone": "telephoneNumber"
  }
}
\`\`\`

⚠️ **\`service_urls\` must not be empty.** It is fail-closed: an empty list rejects every login with \`invalid service URL\`. Register JumpServer's CAS landing URL — \`http://<jumpserver>/core/auth/cas/login/\`. Matching is scheme+host exact plus path prefix, so that one entry covers the query string JumpServer appends.`,
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

⚠️ **The server root MUST end with a slash.** django-cas-ng calls \`urljoin(SERVER_URL, "login")\`, and per RFC 3986 the trailing slash decides whether the last path segment is treated as a file (which gets replaced by \`login\`) or a directory (which is preserved). Drop the slash and you end up requesting \`/protocol/cas/login\` with no APP segment → \`404 application not found\`.`,
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

⚠️ **Callback URL**: this is \`CAS_ROOT_PROXIED_AS\` — the base host JumpServer substitutes when assembling the service URL behind a reverse proxy. It is **NOT** a callback path. Do not append \`/core/auth/cas/callback/\` or \`/core/auth/cas/login/\`, or JumpServer builds the doubled path \`/core/auth/cas/login//core/auth/cas/login/\`.

⚠️ **Attribute map**: the default \`{"cas:user": "username"}\` only pulls the username. To sync email + display name, expand the map as shown. MXID's p3/serviceValidate exposes \`uid mail displayName telephoneNumber\` by default.

JumpServer does **not** need a restart after saving (settings live in the DB). Nothing needs to be synced on the MXID side either.`,
      },
      {
        title: '4. v4 deployment pitfalls — DOMAINS / static / single-container web stubs',
        body: `Four issues bite first-time JumpServer v4 operators:

**① DOMAINS is mandatory in v4.** It is the allow-list of host:port values the app will answer on. Without it the login page renders *"Configuration file has problems"*:

\`\`\`yaml
environment:
  DOMAINS: "localhost:4003,host.docker.internal:4003,192.168.x.x:4003"
  SITE_URL: "http://192.168.x.x:4003"
\`\`\`

**② The core container does not serve /static.** Mount the SAME data volume (\`/opt/jumpserver/data\`) into both core and \`jumpserver/web:v4.x-ce\` (the nginx in front of it) so \`/static/*\` returns 200.

**③ Single-container slimming.** The default web nginx config hard-references upstreams named \`chen\` / \`koko\` / \`lion\`. Without those containers nginx aborts at startup with *"host not found in upstream"*. Stub the includes:

\`\`\`yaml
jms-web:
  volumes:
    - ./empty.conf:/etc/nginx/includes/chen.conf:ro
    - ./empty.conf:/etc/nginx/includes/koko.conf:ro
    - ./empty.conf:/etc/nginx/includes/lion.conf:ro
\`\`\`

(\`empty.conf\` is a single comment line.) Asset terminal connections will be unavailable, but the Web UI + SSO work end-to-end.

**④ Network alias** so JumpServer's nginx can resolve its core upstream by the hard-coded name:

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
1. **Manual** — the admin assigns roles in the JumpServer UI. Fine for < 100-user demos / small teams.
2. **User groups** — set \`group_attribute: "groups"\` on the MXID app so group codes are emitted, then patch \`apps/authentication/backends/cas/views.py\` with a signal that syncs the CAS \`groups\` attribute into JumpServer user groups. High maintenance overhead — you own the patch across upgrades.
3. **EE OIDC** — JumpServer EE's OIDC integration supports \`role_attribute_path\`, which can map roles out of a \`groups\` or \`app_roles\` claim.

**If the user already exists, SSO will not overwrite attributes**: JumpServer pairs the CAS principal against the local username and signs the user in as that local account (a "proxy login"). It does not update email / name. To test attribute sync, sign in as a **new** user that does not yet exist locally, so JumpServer provisions it from the CAS payload.`,
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

JumpServer fetches \`{{ISSUER}}/protocol/oidc/.well-known/openid-configuration\` automatically. If discovery fails with a 403 or an HTML parse error, MXID is not receiving \`X-Forwarded-Proto: https\` — see the OIDC protocol reference.`,
      },
    ],
    notes: [
      '⚠️ Override the platform default subject_strategy (persistent_id) to username on every new CAS app — otherwise cas:user is a numeric ID.',
      '⚠️ The MXID server URL MUST end with a slash because of django-cas-ng urljoin behaviour.',
      '⚠️ The JumpServer "callback URL" is the root URL only (no path) — it is CAS_ROOT_PROXIED_AS, not a real callback path.',
      'v4 requires the DOMAINS env var; without it the login page errors out with "Configuration file has problems".',
      '⚠️ service_urls is fail-closed: leave it empty and every login is rejected with "invalid service URL". Register http://<jumpserver>/core/auth/cas/login/.',
      'CAS 1.0 / 2.0 / 3.0 are all served; configure JumpServer for version 3 (p3/serviceValidate) so attributes come through.',
      'CAS has no SP→IdP logout channel: signing out of JumpServer does not propagate back to MXID. The reverse works — an MXID logout back-channels a logoutRequest to JumpServer.',
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
    summary: 'Harbor v2.x ships native OIDC support and auto-creates project membership from group claims.',
    steps: [
      {
        title: '1. MXID app',
        body: `Protocol OIDC / code \`harbor\` / Redirect URI \`https://<harbor>/c/oidc/callback\`.

**Required**: edit the app's \`protocol_config\` and add claim mappers so Harbor can see groups:

\`\`\`json
{
  "claim_mappers": [
    {"claim": "groups", "source": "user.groups.codes"},
    {"claim": "email",  "source": "user.email"},
    {"claim": "name",   "source": "user.display_name"}
  ]
}
\`\`\`

Without the \`groups\` mapper the userinfo response has no group list, so every SSO user lands in Harbor with no project membership at all.`,
      },
      {
        title: '2. Harbor configuration',
        body: `Harbor Administration → Configuration → Authentication → set the mode to **OIDC**:

\`\`\`
OIDC Provider name        MXID
OIDC Endpoint             {{ISSUER}}/protocol/oidc
OIDC Client ID            <client_id>
OIDC Client Secret        <client_secret>
Group claim name          groups
OIDC Admin Group          mxid-admins
Scope                     openid,profile,email,offline_access
Verify Certificate        off in dev, on in production
\`\`\`

⚠️ \`offline_access\` is **required** here, not optional decoration: Harbor exchanges a refresh token to keep the docker CLI robot session alive, and MXID only issues a refresh token when that scope is requested.

Harbor's "OIDC Endpoint" is the issuer, i.e. \`{{ISSUER}}/protocol/oidc\` — Harbor appends \`/.well-known/openid-configuration\` itself.`,
      },
      {
        title: '3. Verify',
        body: `Click **LOGIN WITH OIDC** on the Harbor login page → authenticate in MXID → land back in Harbor.

Harbor creates project membership from the \`groups\` claim: a user in the group named by *OIDC Admin Group* becomes a Harbor system admin; other groups can be attached to projects as members.

For \`docker login\`, users must first open **User Profile → CLI secret** in Harbor — an OIDC user's password does not work at the registry endpoint.`,
      },
    ],
    notes: [
      'Harbor requires the offline_access scope to receive a refresh token.',
      'subject_strategy=persistent_id is recommended — Harbor binds the local account to sub permanently, so a username change must not change sub.',
      'Without the groups claim mapper every SSO user is provisioned with no project membership.',
      'Group names in Harbor match the MXID group code exactly, case-sensitive.',
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

Access policy: add at least an \`allow public\` rule, or \`allow group=grafana-users\`.

**Protocol config — key: add the claim_mapper to push groups into userinfo**:

\`\`\`json
{
  "claim_mappers": [
    {"claim": "groups", "source": "user.groups.codes"}
  ]
}
\`\`\`

Without this, userinfo has no \`groups\` array, Grafana's \`role_attribute_path\` cannot find a group list, and every user falls back to Viewer.`,
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

⚠️ **auth_url uses the browser-facing host, token_url / api_url use the container-facing host.** auth_url is a 302 that the browser follows — it must resolve from the user's machine. token_url / api_url are HTTP requests made *by* the Grafana container, where \`localhost\` would mean Grafana itself; \`host.docker.internal\` reaches the host's MXID backend. (In a normal HTTPS production deployment all three are the same public URL and this problem disappears.)`,
      },
      {
        title: '3. Verification',
        body: `1. Open Grafana's login page in an incognito window.
2. Click **Sign in with MXID** → bounce to the MXID OIDC authorize endpoint → enter credentials.
3. Confirm the "Sign in to Grafana?" page (SP-initiated logins always show it) → back to Grafana at \`/login/generic_oauth\`.
4. Grafana's backend calls \`/oidc/token\` + \`/oidc/userinfo\` → reads \`sub\` + \`groups\` → auto-provisions the user → computes the role via \`role_attribute_path\`.
5. Land in the dashboard. Grafana \`Server Admin → Users\` shows the new user with login type \`OAuth\`.`,
      },
    ],
    notes: [
      '⚠️ The MXID app must include the claim_mapper {claim:"groups", source:"user.groups.codes"}, otherwise Grafana never sees groups and everyone is Viewer.',
      '⚠️ In docker, auth_url must be browser-reachable and token/api container-reachable (on Linux add extra_hosts: host.docker.internal:host-gateway).',
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

The \`MXID\` segment in that path is the **auth source name** you will type into Gitea in the next step — the two must match character for character, including case.`,
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
\`\`\`

Leave the additional scopes field empty unless you need groups; if you do want group-based team sync, add \`groups\` to the scopes and add the \`{"claim":"groups","source":"user.groups.codes"}\` claim mapper on the MXID app.

After saving, the login page shows a **Sign in with MXID** button.`,
      },
    ],
    notes: [
      'The auth-source name and the callback URL slug must match exactly, including case — a mismatch produces a redirect_uri error at the authorize step.',
      'If discovery fails with an HTML parse error, MXID is not receiving X-Forwarded-Proto: https from the proxy.',
    ],
  },

  /* ─────────────── Atlassian (Jira / Confluence) ─────────────── */
  {
    slug: 'jira-saml',
    app: 'Jira (Cloud / Data Center)',
    protocol: 'saml',
    difficulty: 2,
    tags: ['Atlassian', 'Collab', 'SAML'],
    summary: 'Atlassian standardises on SAML 2.0; the NameID must be the user email.',
    steps: [
      {
        title: '1. MXID app',
        body: `Create the app:

- Protocol: **SAML**
- Code: \`jira\`
- subject_strategy: **email** (Atlassian keys accounts off the email address)

Then edit \`protocol_config\`:

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
\`\`\`

Take \`acs_url\` and \`sp_entity_id\` from Jira's own SAML configuration screen rather than assuming — Cloud and Data Center differ, and Data Center appends the context path if Jira is not at the domain root.`,
      },
      {
        title: '2. Fetch the IdP metadata',
        body: `\`\`\`
{{ISSUER}}/protocol/saml/jira/metadata
\`\`\`

Open it in a browser to download the XML, or hand Jira the metadata URL directly so it re-fetches on certificate rotation.`,
      },
      {
        title: '3. Configure Jira',
        body: `**Jira Cloud**: Atlassian Admin → Security → SAML single sign-on → upload the metadata XML. Requires an **Atlassian Access / Guard** subscription and a verified domain.

**Jira Data Center**: System → Authentication → SAML Authentication.

Values to enter:
\`\`\`
Single sign-on issuer (IdP Entity ID)
   {{ISSUER}}
Identity provider single sign-on URL
   {{ISSUER}}/protocol/saml/jira/sso
X.509 Certificate
   <copy from the metadata>
Username mapping
   email
\`\`\`

Note the IdP Entity ID is the bare issuer origin — MXID uses the same EntityID for every SAML app and varies only the SSO/SLO locations.`,
      },
      {
        title: '4. Verify',
        body: `Sign out of Jira, then hit any Jira page: you should be redirected to MXID, authenticate, and land back in Jira as the matching account.

If Jira rejects the response, the two usual causes are (a) NameID is not the email — check \`subject_strategy=email\` on the MXID app, and (b) the SP Entity ID in \`protocol_config\` does not exactly match what Jira sends in its AuthnRequest.`,
      },
    ],
    notes: [
      'Atlassian rejects SAML responses whose NameID is not the user email — set subject_strategy=email, not just name_id_format.',
      'Atlassian Cloud requires an Atlassian Access / Guard subscription plus a verified domain before SAML can be enabled.',
      'Jira Cloud does not support SAML Single Logout; signing out of Jira leaves the MXID session alive.',
      'For a shared cross-tenant app, keep the tenant_code attribute so Jira-side reporting can tell users apart.',
    ],
  },
  {
    slug: 'confluence-saml',
    app: 'Confluence',
    protocol: 'saml',
    difficulty: 2,
    tags: ['Atlassian', 'Collab', 'SAML'],
    summary: 'Identical to the Jira setup — only the ACS URL changes.',
    steps: [
      {
        title: '1. MXID app',
        body: `Follow the Jira guide, but use the code \`confluence\` and point the ACS URL at Confluence:

\`\`\`
https://<confluence-domain>/plugins/servlet/samlconsumer
\`\`\`

Everything else — \`subject_strategy=email\`, the emailAddress NameID format, the attribute mapping — stays the same. Create it as a **separate** MXID app rather than reusing the Jira one: SAML endpoints are per app_code, and one app can only carry one ACS URL.`,
      },
      {
        title: '2. Confluence side',
        body: `Data Center: General Configuration → Security → SAML Authentication → import the metadata from \`{{ISSUER}}/protocol/saml/confluence/metadata\`.

Cloud: Confluence is covered by the same Atlassian Admin SAML configuration as Jira — configure it once in Atlassian Admin and both products use it. In that case you do **not** need a second MXID app; the single Atlassian-org SAML config serves both.

Many on-prem estates instead front both products with Atlassian Crowd and integrate Crowd once.`,
      },
    ],
    notes: [
      'Atlassian Cloud: Jira and Confluence share one org-level SAML configuration — one MXID app is enough.',
      'Data Center: each product needs its own MXID app because the ACS URL differs and MXID scopes SAML endpoints per app_code.',
    ],
  },

  /* ─────────────── AWS ─────────────── */
  {
    slug: 'aws-saml',
    app: 'AWS Console',
    protocol: 'saml',
    difficulty: 3,
    tags: ['AWS', 'Cloud', 'SAML'],
    summary: 'Federate into AWS via a SAML identity provider. IAM Identity Center is the supported path.',
    steps: [
      {
        title: '1. Pick the right AWS integration',
        body: `AWS offers two SAML federation models, and the difference matters for MXID:

**① IAM Identity Center (formerly AWS SSO) — recommended.** You register MXID as the external identity provider for your AWS organization. Identity Center handles account/permission-set assignment itself, so the SAML assertion only has to identify the user. This works with MXID today, out of the box.

**② Direct IAM SAML federation into the console.** IAM requires the assertion to carry a \`https://aws.amazon.com/SAML/Attributes/Role\` attribute whose value is the literal string \`<role_arn>,<provider_arn>\`. MXID has **no static/constant attribute mapper** — \`attribute_mapping\` can only project the five user fields (username / email / display_name / phone / avatar), and role and group codes are capped at 64 characters, which an ARN pair (~85 chars) exceeds. **Model ② is therefore not supported today.** Use Identity Center.`,
      },
      {
        title: '2. Register the identity provider in AWS',
        body: `**IAM Identity Center** → Settings → Identity source → Change to **External identity provider**.

- Download AWS's *service provider metadata* (it contains the ACS URL and the SP Entity ID, e.g. \`https://<region>.signin.aws.amazon.com/platform/saml/acs/<id>\` and \`https://<region>.signin.aws.amazon.com/platform/saml/<id>\`).
- Upload MXID's IdP metadata from \`{{ISSUER}}/protocol/saml/aws/metadata\`, or paste the metadata URL.

(If you are instead registering a raw IAM identity provider: IAM → Identity providers → Add provider → SAML → upload the same MXID metadata. Note the provider ARN, then see step 1 ② for why role mapping does not work yet.)`,
      },
      {
        title: '3. MXID app configuration',
        body: `Protocol SAML / code \`aws\`, with \`protocol_config\` taken from the AWS SP metadata you downloaded:

\`\`\`json
{
  "acs_url": "https://<region>.signin.aws.amazon.com/platform/saml/acs/<id>",
  "sp_entity_id": "https://<region>.signin.aws.amazon.com/platform/saml/<id>",
  "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  "attribute_mapping": {
    "email": "email",
    "display_name": "displayName"
  },
  "session_ttl": 28800
}
\`\`\`

Set the app's subject strategy to \`email\` or \`persistent_id\` — whichever matches the user matching rule you configured in Identity Center. Identity Center matches on the NameID, so it must be stable: never point it at a mutable username.

You must still create (or SCIM-provision) the users inside Identity Center and assign them to accounts and permission sets; SAML authenticates the user, it does not authorize them.`,
      },
    ],
    notes: [
      'Use IAM Identity Center. Direct IAM console federation needs a static Role attribute (<role_arn>,<idp_arn>) that MXID cannot emit — there is no constant attribute mapper, and role/group codes are limited to 64 characters.',
      'AWS requires a stable NameID: subject_strategy=email or persistent_id, never a mutable username.',
      'Copy acs_url and sp_entity_id out of the AWS-provided SP metadata rather than hand-typing them — they are region- and instance-specific.',
      'Federated console session duration is governed by the assumed role in AWS (1h default), not by session_ttl.',
    ],
  },

  /* ─────────────── Jenkins ─────────────── */
  {
    slug: 'jenkins-cas',
    app: 'Jenkins',
    protocol: 'cas',
    difficulty: 2,
    tags: ['CI/CD', 'CAS'],
    summary: 'Jenkins CAS Plugin — old but rock-solid. Prefer OIDC on modern Jenkins.',
    steps: [
      {
        title: '1. MXID app',
        body: `Protocol **CAS** / code \`jenkins\`.

\`protocol_config\`:
\`\`\`json
{
  "service_urls": ["https://<jenkins>/securityRealm/finishLogin"],
  "ticket_ttl": 60,
  "role_attribute": "roles",
  "attribute_mapping": {
    "email": "mail",
    "display_name": "cn",
    "username": "uid"
  }
}
\`\`\`

\`service_urls\` is fail-closed — leaving it empty rejects every login with \`invalid service URL\`. \`https://<jenkins>/securityRealm/finishLogin\` is where the Jenkins CAS plugin lands.`,
      },
      {
        title: '2. Install the CAS plugin',
        body: 'Manage Jenkins → Plugins → Available → install **CAS Plugin** → restart Jenkins. Keep one known-good local admin account before you switch the security realm, so a misconfiguration cannot lock you out.',
      },
      {
        title: '3. Configure the security realm',
        body: `Manage Jenkins → Security → Security Realm → **CAS**:

\`\`\`
CAS Server URL:     {{ISSUER}}/protocol/cas/jenkins/    ← trailing slash
CAS Protocol:       CAS 3.0
\`\`\`

Choose **CAS 3.0**, not the 1.0 default — only 3.0 returns attributes, so 1.0 gives you a username and nothing else (no email, no display name, no roles).

For authorization, use **Matrix Authorization Strategy** and create groups whose names equal the role codes MXID emits in the \`roles\` attribute (case-sensitive). JIT-elevated roles appear first in that attribute and disappear when the grant expires, so a temporary elevation shows up in Jenkins automatically.

If you lock yourself out, set \`useSecurity\` to false in \`JENKINS_HOME/config.xml\` and restart.`,
      },
    ],
    notes: [
      'The Jenkins CAS plugin defaults to CAS 1.0 — select CAS 3.0 or you get no attributes at all.',
      'service_urls is fail-closed: register https://<jenkins>/securityRealm/finishLogin before testing.',
      'On a current Jenkins, the oic-auth (OpenID Connect Authentication) plugin is the better integration: it supports back-channel logout and group-based role mapping. Do not confuse it with "OpenID Connect Provider", which points Jenkins the other way round.',
      'Keep a local admin account while switching the security realm; roll back via useSecurity=false in JENKINS_HOME/config.xml.',
    ],
  },

  /* ─────────────── Lark / Feishu (login MXID itself) ─────────────── */
  {
    slug: 'lark-login',
    app: 'Lark / Feishu → MXID',
    protocol: 'oidc',
    difficulty: 1,
    tags: ['External IdP', 'Lark', 'Feishu'],
    summary: 'Add a "Sign in with Lark" button to the MXID portal so employees log in without a password.',
    steps: [
      {
        title: '1. Create the app on the Lark / Feishu open platform',
        body: `https://open.larksuite.com/app (international) or https://open.feishu.cn/app (China).

- Create a **custom internal app**.
- Under *Credentials & Basic Info*, copy the **App ID** and **App Secret**.
- Under *Security Settings* → redirect URLs, add:
  \`\`\`
  {{ISSUER}}/api/v1/portal-public/auth/external/lark/callback
  {{ISSUER}}/api/v1/console-public/auth/external/lark/callback
  \`\`\`
  The last path segment before \`/callback\` is the **identity-source code** you will enter in MXID — they must match. Add the console callback too if administrators should also be able to sign into the console with Lark.
- Under *Permissions*, grant: read basic user profile / email / mobile number.
- Under *Version & Release*, publish the app or add yourself as a test user — an unreleased app returns an authorization error for everyone else.`,
      },
      {
        title: '2. Add the identity source in the MXID console',
        body: `Sidebar → **Identity sources** → **New**:

\`\`\`
Type          Lark (international) or Feishu (China)
Name          Lark
Code          lark               ← must match the callback URL segment
App ID        <copied from the Lark console>
App Secret    <copied from the Lark console>
Enabled       ✓
Auto-provision users  ✓
\`\`\`

The dialog shows the exact portal and console callback URLs for the code you typed — copy them from there rather than hand-assembling.

**Note**: external identity providers are an **Enterprise Edition** feature. On the community edition the Identity sources page is gated.`,
      },
      {
        title: '3. Test the login',
        body: `Open the portal login page:

\`\`\`
{{PORTAL}}/
\`\`\`

A **Lark** button appears at the bottom → click it → approve in Lark → you are returned to MXID, the account is provisioned on first login, and you land on the portal app grid.

If a force-MFA policy is in effect, federated users are still challenged for MFA after the Lark hand-off — Lark authenticates the identity, it does not satisfy the second factor.`,
      },
    ],
    notes: [
      'Users are matched by email. A different email means a different MXID user — accounts are never merged automatically.',
      'External-IdP users can be given a local password afterwards (portal self-service or console) so they keep both login paths.',
      'MXID MFA policy still applies to federated logins — Lark login does not bypass a required second factor.',
      'External IdP is an Enterprise Edition feature (feature key `external_idp`).',
    ],
  },
]
