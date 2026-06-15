# Changelog

All notable changes to MXID are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- AGPL v3.0 license declared, README rewritten, SECURITY policy.
- `.github/` issue + PR templates.
- `docs/DEPLOYMENT.md`, `docs/ARCHITECTURE.md`.

## [1.0.0] — 2026-06-15

First stable release.

### Added
- **Icon storage in database** — app/org icons are now stored as BLOBs in the
  database rather than on the local filesystem. The backend is stateless (no PVC
  required for Kubernetes), icons survive container restarts, and all replicas
  serve consistent data. Single-file size limit: 2 MB.
- **`make prod-docker-up`** — new Makefile target for production compose
  orchestration; dev and prod nginx containers now use distinct names to avoid
  conflicts when both stacks are present on the same host.

### Changed
- **Platform-level config physical isolation** — license and install-fingerprint
  records have been moved to dedicated tables, isolated from tenant-scoped
  settings. This fixes startup-time read failures that occurred when the settings
  loader ran without a valid tenant scope, which caused the install fingerprint to
  drift between restarts in multi-tenant setups.
- **Tenant-scope root-cause fix** — settings reads that run outside a scoped
  context (background tasks, startup, platform-level reads) now explicitly inject
  the correct tenant, rather than falling through to an empty scope and silently
  returning defaults.
- **`/system/info` feature advertisement by binary capability** — `features` now
  reflects only what the running binary actually contains. Code-separated features
  (`external_idp`, `webauthn`, `scim`, …) are published only when the EE binary
  is running and has registered them; they are never listed for the CE binary even
  if an EE license is active.
- **External IdP callback and post-login redirect URLs resolved at runtime** —
  callback and redirect URLs for external IdP flows are now read from the live
  console configuration on each request, removing the need to restart after
  changing `ExternalURLs` settings.

### Fixed
- **Logout global cleanup** — sign-out now terminates all active sessions across
  console, portal, and protocol layers in a single operation. Previously, logging
  out of one surface left the others active.

## [0.1.0] — 2026-06-10

Initial public preview. Two integrations verified end-to-end: **Grafana (OIDC)** and **JumpServer v4 (CAS 3.0)**.

### Protocols
- OIDC 1.0: Authorization Code + PKCE, Refresh, Implicit, Hybrid, Client Credentials. Discovery, JWKS, RP-Initiated + Back-channel Logout. Per-app claim mappers.
- SAML 2.0: IdP- + SP-initiated, SHA-256 signed assertions, SLO, per-app attribute mapping.
- CAS 3.0: `serviceValidate`, `p3/serviceValidate`, per-app `service_urls` allowlist + `ticket_ttl` + `attribute_mapping`.
- JWT: HS256 / RS256 app-shared secret.

### Identity
- Local users with password policy (length, character classes, history, expire, lockout, captcha).
- MFA: TOTP (RFC 6238) + backup recovery codes.
- External IdPs: Lark / Feishu / Microsoft Teams.
- Per-app access policies (user / group / org / role / public).
- Per-app roles propagated as `app_roles` claim.
- Sessions in Redis with runtime idle/absolute/remember-me from `SecurityPolicy.Session`.

### Operations
- Setting domain (hot-reload): `MailSMTP`, `MailTemplates`, `SecurityPolicy`, `LoginMethods`, `Branding`, `Localization`, `SMS`, `AuditPolicy`, `License`, `ProtocolDefaults`, `ExternalURLs`.
- Audit retention cron (6h tick) reads `AuditPolicy.RetentionDays`.
- License quota enforcement on user / tenant create.
- Mailer flows: email verification, password reset, magic-link, welcome.
- SMS senders: Aliyun (HMAC-SHA1), Tencent Cloud (TC3-HMAC-SHA256 v3), Twilio.
- Portal public endpoints (pre-auth): password forgot/reset, magic-link send/callback, SMS OTP send/login.
- `pkg/urlswap`: handlers resolve `Provider` URLs → swap `localhost` to inbound request host. Works for dev / LAN-IP without config changes.

### Console UI
- Settings pages for every setting type with `GenericForm` + typed coerce (csv/int/json/bool) for CAS protocol_config.
- Integration docs at `/docs` — Grafana, JumpServer, Harbor, Gitea, Jira, Confluence, AWS, Jenkins, Lark playbooks.
- App icon library: simple-icons subset + hand-crafted JumpServer SVG.
- Multi-namespace i18n (16 namespaces × zh-CN / en-US).
- Toast notifications (top-center) shared by console + portal.

### Portal UI
- Login + MFA challenge + external IdP buttons + magic-link + SMS OTP + password reset.
- Apps grouped (favorites / recent / all), drag-drop favorites.
- Profile, security, sessions, login history, MFA enroll.
- SSO resume: portal detects `?protocol=cas&app_code=&service=` on /login, bounces back through the protocol endpoint after credentials succeed.

### Infrastructure
- PostgreSQL 32 migrations covering users / tenants / orgs / groups / apps / audit / sessions / api tokens / favorites.
- Redis 7 for sessions, tickets, TOTP rate-limit, event SSE.
- Docker compose dev stack (air hot reload) + production compose example.
- pnpm workspaces (`console` / `portal` / `shared`).
- Tailwind v4 monorepo `@source` directive so shared package UI compiles into both SPAs.

[Unreleased]: https://github.com/imkerbos/mxid/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/imkerbos/mxid/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/imkerbos/mxid/releases/tag/v0.1.0
