# Architecture

Reading order: start with the [README architecture diagram](../README.md#architecture), then come here for the deeper breakdown of why each layer exists and where to extend it.

## Process layout

MXID is one Go binary serving:

- Backend REST API at `/api/v1/{console,portal,openapi}/...`
- Public bootstrap endpoint at `/api/v1/system/bootstrap` (pre-auth)
- Protocol gateway at `/protocol/{oidc,saml,cas,jwt}/...`
- Static console + portal SPAs (mounted in production builds)

The SPAs are independent pnpm workspaces (`web/apps/{console,portal}`) sharing a third workspace (`web/packages/shared`) for API client, i18n, and UI primitives.

## Layered packages

```
cmd/server/                  binary entrypoint + thin adapter glue (1 file ~700 LOC, intentional god-file per project memory)
└── internal/
    ├── bootstrap/           viper config, gorm wiring, snowflake IDs, router, structured logger
    ├── domain/              one package per business capability
    │   ├── user/            local accounts, MFA, password history
    │   ├── tenant/          multi-tenant model
    │   ├── app/             SP registration + protocol_config + access policy
    │   ├── authn/           login orchestration, captcha, MFA challenge, login policy
    │   ├── audit/           append-only log + retention
    │   ├── setting/         hot-reload runtime config (the central knob)
    │   ├── consent/         OIDC scope consent grants
    │   ├── appaccess/       per-app allow/deny rules
    │   ├── approle/         per-app role bindings
    │   ├── externalidp/     Lark / Feishu / Teams (and any others added via providers/)
    │   ├── apitoken/        headless API tokens
    │   ├── org/             org tree (departments)
    │   ├── group/           static + dynamic user groups
    │   └── permission/      role-based authz primitive
    ├── protocol/            stateless protocol handlers
    │   ├── oidc/            authorize, token, userinfo, revoke, introspect, end_session, jwks, discovery
    │   ├── saml/            metadata, sso (POST + redirect bindings), slo
    │   ├── cas/             login, validate, serviceValidate, p3/serviceValidate, logout
    │   └── resolver/        AppResolver / IdentityResolver / SessionResolver / TenantResolver — interfaces protocols use to read domain state without importing domain packages
    ├── gateway/             HTTP boundary
    │   ├── console/         admin REST surface (CRUD over domain)
    │   └── portal/          end-user REST + SSO bounce + magic-link / SMS / password-reset
    └── middleware/          cors, structured logger, request-id propagation
└── pkg/                     reusable libs
    ├── event/               in-process pub-sub bus
    ├── mailer/              SMTP + Go text/template templates
    ├── sms/                 Aliyun / Tencent / Twilio senders
    ├── session/             redis-backed session manager
    ├── urlswap/             canonical-URL resolution (admin setting → defaults → request-host swap)
    ├── snowflake/           globally unique IDs
    ├── crypto/              AES + bcrypt helpers
    └── authz/               role + scope check primitives
```

### Why this shape

- **Domain packages own their model + service + repository**. They expose narrow interfaces. Gateways import domain services; domain packages never import gateways.
- **Protocol handlers are stateless** and read state through `resolver` interfaces. Adding a new protocol (e.g. WS-Federation) means a new `internal/protocol/wsfed/` package and a few adapter functions wired in `cmd/server`.
- **Setting domain is the runtime config bus**. Every operationally-adjustable knob lives here. Handlers read settings via per-tenant accessors. Admin UI is a CRUD over the same shape. No restart required for any operational change.
- **`pkg/` is for libraries that don't know about MXID's business model**. Anything in `pkg/` could theoretically be open-sourced as a separate dependency.

## Data flow — OIDC authorization code

```
Browser                Portal SPA            MXID backend                  External SP
   │                       │                       │                            │
   │  click "Login w/MXID" │                       │                            │
   ├──────────────────────────────────────────────────────────────────────────► │
   │                       │                       │                            │
   │ ◄────302 to /protocol/oidc/authorize?...─────────────────────────────────┤
   │                       │                       │                            │
   ├─/protocol/oidc/authorize─────────────────────►│                            │
   │                       │                       │                            │
   │ ◄─302 to /login?return_to=...─────────────────┤  (no session)              │
   │                       │                       │                            │
   ├─GET /login───────────►│                       │                            │
   │                       │                       │                            │
   ├─POST /api/v1/portal/auth/login ─────────────► │  authn.engine: pwd + MFA  │
   │                       │                       │                            │
   │ ◄────── 200 (cookie set) ─────────────────────│                            │
   │                       │                       │                            │
   ├─window.location.replace(return_to)─►          │                            │
   │                       │                       │                            │
   ├─/protocol/oidc/authorize (with cookie)──────► │  consent + access check    │
   │                       │                       │                            │
   │ ◄─302 to SP's redirect_uri?code=…─────────────│                            │
   │                       │                       │                            │
   ├─SP redirect_uri?code=…──────────────────────────────────────────────────► │
   │                       │                       │                            │
   │                       │                       │ ◄─POST /protocol/oidc/token (server-side)
   │                       │                       ├──────►id_token + access_token
   │                       │                       │                            │
   │ ◄─SP's "logged in" page──────────────────────────────────────────────────│
```

CAS and SAML follow the same general shape with protocol-specific details.

## Settings domain — the hot-reload bus

Operational config is split into typed groups:

| Group | Reads | Writes (UI) |
|-------|-------|-------------|
| `MailSMTP` | `pkg/mailer` per send | Settings → SMTP |
| `MailTemplates` | `pkg/mailer` template render | Settings → Mail Templates |
| `SecurityPolicy` | `authn.engine` for lockout, `user.Service` for password rules, `session.Manager` for TTL | Settings → Security |
| `LoginMethods` | portal login UI + authn.engine method gate | Settings → Login methods |
| `Branding` | portal /bootstrap → SPA applies primary color, title, custom CSS | Settings → Branding |
| `Localization` | portal /bootstrap → i18n default + tz | Settings → Localization |
| `ProtocolDefaults` | `app.Service.Create` applies on new apps | Settings → Protocol defaults |
| `SMS` | `pkg/sms` per send | Settings → SMS |
| `AuditPolicy` | retention cron + alert dispatch | Settings → Audit |
| `License` | `user.Service.Create` / `tenant.Service.Create` quota | Settings → License |
| `ExternalURLs` | every protocol handler via `urlswap.Resolve` | Settings → External URLs |

Sensitive fields (SMTP password, SMS secret) are AES-encrypted with `MXID_MASTER_KEY` at write time, decrypted on read. The encryption pipeline is in `setting.Service` — adding a new sensitive field requires only registering it in `sensitiveFields`.

## URL resolution

Every protocol handler resolves URLs via `pkg/urlswap.Resolve(provider, defaults, reqHost)`:

1. If the admin set `ExternalURLs.IssuerURL` / `PortalURL` / `ConsoleURL` in settings, those win.
2. Else fall back to `bootstrap.Config.Server.{IssuerURL,PortalURL,ConsoleURL}`.
3. If the resolved host is `localhost` / `127.0.0.1` AND the inbound request hit a different host (LAN IP, override domain), the host is swapped to the inbound host (port preserved).

This means dev / LAN testing works without admin intervention, while prod canonical URLs are honored verbatim.

## SPA architecture

`web/packages/shared` is the cross-app library:

- `api/` — axios clients per domain (one file per resource).
- `i18n/` — i18next + 16 namespace bundle in `locales/{zh-CN,en-US}.ts`.
- `hooks/` — React hooks (`useAuthStore`, `useBootstrap`, `useTranslation` re-export).
- `ui/` — `Toaster`, `IconPicker`, `AppIcon`.
- `utils/` — `cn`, `formatDate` (locale + tz aware), `statusLabel` (i18n-aware), `parseUserAgent`.

Each SPA imports from `@mxid/shared/...` paths. Tailwind v4 needs an `@source` directive in each app's `index.css` to scan shared package files; without it, classes used only in `Toaster` etc. are tree-shaken out.

## Multi-tenancy model

- One PostgreSQL table per resource is partitioned by `tenant_id`.
- The default tenant (`id=1`) is created on first migration.
- Apps may be `scope=tenant` (visible only to that tenant) or `scope=shared` (visible to all tenants).
- Protocols infer the tenant from session, or from a `?tenant=<code>` query parameter on the portal login URL.

## Extending — add a new external IdP

1. Implement the `externalidp/providers.Provider` interface.
2. Register the provider type in `internal/domain/externalidp/providers/init.go`.
3. Add UI: the IdP CRUD page (`web/apps/console/src/pages/idps`) will pick up the new `type` from the API automatically; add an icon + label only if you want them branded.

## Extending — add a new protocol

1. New package under `internal/protocol/<name>/`.
2. Implement handler, route registration, and ticket / token store as needed.
3. Add `<name>.Register(...)` call in `cmd/server/main.go`, alongside CAS / SAML / OIDC.
4. Add a row to `app.Protocol` constants + `ProtocolDefaults` setting + UI dropdown.

## Things deliberately not done (yet)

- **Federation across MXID instances.** Single-instance only.
- **WebAuthn / FIDO2** — only TOTP for MFA today.
- **SCIM** — no user provisioning protocol yet.
- **DPoP / OAuth 2.1 strict mode** — token endpoint stays on Bearer.
- **JIT user provisioning from external IdP** — exists per-IdP but not configurable through UI.

These are all candidate features for future versions.
