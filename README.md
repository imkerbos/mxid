<div align="center">

# MXID

**Open-source Enterprise Identity and Access Management (IAM/SSO) Platform**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)](https://go.dev)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7+-DC382D?logo=redis&logoColor=white)](https://redis.io)
[![Issues](https://img.shields.io/github/issues/imkerbos/mxid)](https://github.com/imkerbos/mxid/issues)
[![Stars](https://img.shields.io/github/stars/imkerbos/mxid?style=social)](https://github.com/imkerbos/mxid/stargazers)

English · [简体中文](#中文)

</div>

---

MXID is a self-hosted IAM platform: a single login portal, an admin console, and a protocol gateway that speaks **OIDC**, **SAML 2.0**, **CAS 3.0**, and **JWT** so any of your apps can plug into one identity layer. Built for commercial-grade deployments — multi-tenant, multi-language, and benchmarked against Keycloak / Auth0 / Okta / TopIAM.

## Features

### Protocols
- **OIDC 1.0** — Authorization Code + PKCE, Refresh Token, Client Credentials, Implicit (legacy), Hybrid. Discovery, JWKS, RP-Initiated + Back-channel Logout. Per-app claim mappers (`groups`, `roles`, etc.).
- **SAML 2.0** — IdP-initiated and SP-initiated. SHA-256 signed assertions. SLO. Per-app attribute mapping.
- **CAS 3.0** — `serviceValidate`, `p3/serviceValidate` (with attributes). Per-app service URL allowlist + ticket TTL.
- **JWT** — App-shared HS256 / RS256 secret, suitable for internal service-to-service.

### Identity
- Local users + password policy (min length, character classes, **history N**, expire days, lockout, captcha).
- **MFA**: TOTP (RFC 6238 — Google Authenticator / Authy / 1Password), backup recovery codes.
- **External IdPs** (per-tenant): Lark / Feishu / Microsoft Teams (more pluggable via `pkg/externalidp/providers`).
- Per-app access policies (allow / deny by user / group / org / role / public).
- Per-app roles (`admin`, `viewer`, …) propagated as claims.
- Sessions in Redis. Idle + absolute timeout configurable at runtime.

### Operations
- **Multi-tenant** — global apps + per-tenant apps, with tenant code prefixed paths.
- **i18n** — built-in Chinese + English; admin sets default; per-user override.
- **Branding** — admin-supplied product name, primary color, logo, login footer HTML, custom CSS.
- **Email** — SMTP runtime config. Templates for email verification, password reset, magic-link, welcome.
- **SMS OTP** — Aliyun / Tencent Cloud / Twilio (stdlib, no SDK).
- **Magic-link** login (passwordless).
- **Audit log** + retention cron + alert webhook.
- **License** — quota enforcement on user / tenant count; enterprise feature gate.
- **API tokens** for headless integrations (OpenAPI under `/api/v1/openapi`).

### Architecture
- Go backend (Gin + GORM + Redis + Snowflake IDs + bcrypt).
- React 19 + Vite 8 + TypeScript + Tailwind (pnpm workspaces: `console`, `portal`, `shared`).
- PostgreSQL primary store, Redis for sessions / tickets / TOTP rate-limit / event SSE.
- Settings-domain layer: every operational knob (SMTP, policy, branding, URLs…) is admin-editable at runtime; no rebuild required.

## Architecture

```
                       ┌────────────────────────────────┐
                       │            End User            │
                       └───────────────┬────────────────┘
                                       │
                                       ▼
                       ┌────────────────────────────────┐
                       │   Portal SPA (Vite + React)    │
                       │   /login /consent /apps        │
                       └───────────────┬────────────────┘
                                       │ session cookie
                                       ▼
        ┌───────────────────────────── MXID Backend (Go) ─────────────────────────────┐
        │                                                                              │
        │   ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐    │
        │   │  Protocol Gateway  │  │   AuthN Engine     │  │   Settings Domain  │    │
        │   │  OIDC / SAML / CAS │  │  password + TOTP   │  │  hot-reload runtime│    │
        │   │  JWT               │  │  + external IdP    │  │  SMTP / Branding   │    │
        │   └─────────┬──────────┘  └─────────┬──────────┘  │  Security / URLs   │    │
        │             │                       │             └────────────────────┘    │
        │             └──────────┬────────────┘                                       │
        │                        ▼                                                    │
        │              ┌────────────────────┐  ┌──────────────────┐                  │
        │              │  Identity Resolver │  │  Access / Roles  │                  │
        │              │  user/group/org    │  │  per-app policy  │                  │
        │              └─────────┬──────────┘  └────────┬─────────┘                  │
        │                        │                      │                            │
        │   ┌────────────────────┴──────────────────────┴────────────────────┐       │
        │   │              Console SPA (admin) — /tenants /users /apps        │       │
        │   └────────────────────────────────────────────────────────────────┘       │
        │                                                                              │
        └──────────────────────────────────┬──────────────────────────────────────────┘
                                           │
                  ┌────────────────────────┼────────────────────────┐
                  ▼                        ▼                        ▼
        ┌──────────────────┐   ┌──────────────────┐    ┌──────────────────┐
        │   PostgreSQL     │   │      Redis       │    │   SMTP / SMS     │
        │   tenants/users/ │   │  sessions/       │    │   provider       │
        │   apps/audit ... │   │  tickets/events  │    │                  │
        └──────────────────┘   └──────────────────┘    └──────────────────┘
                  ▲                                              ▲
                  │                                              │
                  └─────────────── External SPs ─────────────────┘
                          Grafana · JumpServer · Jira · Harbor · …
```

## Quick start

### Docker compose (recommended)

```bash
git clone https://github.com/imkerbos/mxid.git
cd mxid
cp .env.example .env
make dev-docker-up                # backend + console + portal + air hot-reload
```

Single entry point through nginx on **port 3500**:

- Portal:  <http://localhost:3500/>            — end-user login + my-apps
- Console: <http://localhost:3500/admin/>      — admin (default `admin` / `admin123!`)
- API:     <http://localhost:3500/api/v1/...>
- OIDC discovery: <http://localhost:3500/protocol/oidc/.well-known/openid-configuration>

The same scheme works in production — just swap the host (`https://id.example.com/`, `/admin/`, `/api/`, `/protocol/`). See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

### Local Go + Node dev

```bash
# Requires Postgres 15 + Redis 7 reachable at the values in configs/config.dev.yaml
make dev          # backend (air hot reload)
make dev-web      # vite dev server for console + portal
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for production (single-domain, multi-domain, reverse proxy, secrets, HTTPS) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the deeper design.

## Integration guides (battle-tested)

The console ships built-in integration docs at `/docs`:

- ✅ **Grafana** (OIDC) — `role_attribute_path` + `claim_mappers` walkthrough.
- ✅ **JumpServer** (CAS) — v4 community edition, includes `DOMAINS`, web container static, `CAS_ROOT_PROXIED_AS`, subject-strategy pitfalls.
- Harbor / Gitea / Jira / Confluence / AWS / Jenkins / Lark — see `web/apps/console/src/pages/docs/guides.ts`.

## Project layout

```
mxid/
├── cmd/server/              # main + thin adapter glue (1 binary)
├── internal/
│   ├── bootstrap/           # config, router, gorm logger, app shell
│   ├── domain/              # one package per business capability
│   │   ├── user/  app/ tenant/ org/ group/ permission/
│   │   ├── authn/ apitoken/ audit/ setting/ consent/
│   │   ├── appaccess/ approle/ externalidp/
│   ├── protocol/            # OIDC / SAML / CAS handlers
│   ├── gateway/
│   │   ├── console/         # admin REST surface
│   │   └── portal/          # end-user REST + SSO bounce + magic-link/SMS/password-reset
│   └── middleware/          # cors, logger, request-id
├── pkg/                     # reusable libs: event, mailer, sms, session, urlswap, …
├── migrations/              # SQL (32+)
├── web/
│   ├── apps/console/        # React admin SPA
│   ├── apps/portal/         # React end-user SPA
│   └── packages/shared/     # cross-app: i18n, api, hooks, ui (toast, icon-picker)
├── configs/                 # config.{yaml,dev.yaml,prod.yaml}
├── deploy/                  # compose / dockerfile / nginx / scripts
├── scripts/                 # smoke-test, pre-commit, install-hooks
└── docs/                    # README -> DEPLOYMENT / ARCHITECTURE
```

## Verification

Both flows reached green status during the v0.1 sprint:

| App | Protocol | Status | Notes |
|-----|----------|--------|-------|
| Grafana | OIDC | ✅ | `groups` claim → `role_attribute_path` → admin/viewer |
| JumpServer v4 | CAS 3.0 | ✅ | user auto-create (source=CAS), `mail` + `displayName` attribute-synced |

See `web/apps/console/src/pages/docs/guides.ts` for the corresponding playbooks.

## Community & contributing

- See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, branch + commit conventions, and the local lint/test pipeline.
- See [SECURITY.md](SECURITY.md) for vulnerability reporting.
- See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Bugs and feature requests on [GitHub Issues](https://github.com/imkerbos/mxid/issues).

## License

MXID is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0). See [LICENSE](LICENSE).

If you run a modified MXID as a network service, the AGPL requires you to publish your modifications under the same license.

---

<a name="中文"></a>

## 中文

MXID 是自托管的开源企业 IAM/SSO 平台。一个登录门户、一个管理控制台、一套覆盖 **OIDC / SAML / CAS / JWT** 的协议网关，让企业内所有应用接入同一身份层。面向商业级部署设计 — 多租户、多语言、对标 Keycloak / Auth0 / Okta / TopIAM。

### 功能亮点

- **协议**: OIDC 1.0 (含 PKCE / Refresh / RP-Initiated Logout)、SAML 2.0、CAS 3.0、JWT
- **认证**: 本地账号 + 密码策略 (强度、历史、失败锁定、验证码) + TOTP MFA + 备用恢复码
- **第三方登录**: Lark / 飞书 / Teams (可插拔)
- **多租户**: 全局应用 + 租户私有应用, code 路径隔离
- **设置热加载**: SMTP / 安全策略 / 品牌 / 登录方式 / 协议默认值 / 对外 URL — admin UI 改, 无需重启
- **邮件 / 短信**: SMTP 模板, 阿里云 / 腾讯云 / Twilio 短信
- **运维**: 审计日志 + 留存 cron, License 配额, API Token
- **i18n**: 内置中英文 + 实时切换

### 一键启动

```bash
git clone https://github.com/imkerbos/mxid.git
cd mxid
cp .env.example .env
make dev-docker-up
```

单端口统一入口 (nginx :3500):

- 门户:   <http://localhost:3500/>
- 控制台: <http://localhost:3500/admin/>
- 接口:   <http://localhost:3500/api/v1/...>
- OIDC:   <http://localhost:3500/protocol/oidc/...>

prod 把 `localhost:3500` 换成你的域名即可, 路径不变.

详细部署见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), 架构设计见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), 协议端点 / 集成示例见控制台 `/admin/docs`.

### 协议

[AGPL v3.0](LICENSE). 把修改后的 MXID 作为网络服务对外提供时, 必须公开修改源码.
