# Changelog

All notable changes to MXID are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- The account page's form labels now match the rest of the console. It declared
  a private copy of the shared `Field` primitive that shadowed the import, so its
  labels were styled differently and it had no slot for a validation message. A
  second unused copy (`FormField`) has been removed as well.

### Security
- A mistyped SAML `sp_cert` is now rejected when the SP descriptor is built.
  Most short strings are valid base64, so garbage decoded cleanly and only
  surfaced later as an opaque signature failure on the SP's next signed
  AuthnRequest.
- External-IdP providers (Lark/Feishu, Teams, GitHub) now make their OAuth calls
  through the SSRF-guarded client instead of a bare HTTP client, so a redirect
  from a compromised IdP cannot walk the request onto an internal address with
  the app's bearer token attached. (EE)
- Five error responses showed the user a message about something else. The SPA
  replaces the server message with a fixed translated sentence for certain
  numeric codes, and those codes had been reused: a bad dynamic-group rule and an
  invalid access-eligibility body both rendered as "this app has no login URL", a
  missing captcha rendered as "that code was just used", and a disabled login
  method and a missing TOTP code both rendered as "that password matches a recent
  one". All five now carry codes of their own.
- Access-policy label resolvers now filter by tenant. They query with `.Table()`
  into anonymous scan structs, which the tenantscope plugin cannot see, so any id
  from any tenant resolved to a name — a cross-tenant label oracle. Request-bound
  callers now carry the predicate; the tenant-less paths (logout terminators,
  background jobs) are unchanged, since they have no tenant to filter by.

### Fixed
- The login captcha could not appear. Both login screens branched on the old
  numeric code for "captcha required", so after the backend moved that code the
  widget was never revealed or fetched — under captcha enforcement, login was
  impossible. The codes are now named constants shared by both screens.
- A captcha that fails to load now says so instead of reading "loading…"
  forever. It is only ever fetched because the backend has made it mandatory,
  so the user could not log in and had no way to tell that from a slow network.
- The organization member list reports a failed load. An empty list and a failed
  request looked identical, so an org could appear to have no members.
- Eight forms did nothing when submitted with a missing or too-short value: the
  group, app and app-group create dialogs (empty code), the API-token dialog
  (empty name), the admin password reset (under six characters), and the portal
  forgot-password, magic-link and SMS-login screens (empty email/phone). Each
  now shows the reason on the field. These were the inputs with no native
  `required` attribute, so nothing stopped the submit and nothing explained it.
- Admin password reset is now one transaction. A partial failure could leave the
  temporary password live without the must-change flag (making it permanent) or
  without a history row (making it reusable past the reuse policy).
- Removing a TOTP factor now deletes its backup codes in the same transaction,
  and only that factor. Previously the backup-code delete ran separately with its
  error discarded, so "MFA removed" could leave working backup codes behind.
- Dynamic-group recompute is debounced per tenant (2s trailing edge). A batch
  action over N users emitted N events, each triggering a full tenant-wide
  recompute; it now runs once.

## [1.8.0] — 2026-07-28

### Added
- Brand asset upload: branding logo/favicon uploadable to `mxid_upload` via
  `POST /upload/brand-logo` (reuses the app-icon DB pipeline — immutable caching,
  SVG byte-sniffing, CSP sandbox); gated by `settings.manage` + `RequireFeature(branding)`.
- `Branding.favicon_url` (empty = reuse `logo_url`).
- Login return URI: re-login returns the user to where the session expired, on both
  SPAs, validated through `safeReturnPath` (rejects absolute / protocol-relative /
  backslash forms and `/login`).
- URL-persisted list state: filters, pagination and tabs live in the URL for console
  users / groups / access-approvals and the portal app grid. `useUrlState` /
  `useTabParam` promoted to `@mxid/shared`.

### Fixed
- App card titles overflowed their card (missing `min-w-0` on the flex parent).

## [1.7.4] — 2026-07-23

### Security
- `golang.org/x/text` → v0.39.0 (GO-2026-5970).

### Changed
- Go + frontend dependency refresh; nginx image aligned. (EE: transitive deps
  synced — x/text v0.40.0, gorm v1.31.2.)

## [1.7.3] — 2026-07-22

### Added
- Batch access policies: `POST .../access-policies/batch` for apps and app-groups,
  with a searchable multi-select subject picker; re-adding an existing subject is an
  idempotent no-op (skipped client- and server-side).
- App list filters by app-group / environment / access-policy + page-size selector
  (10/20/50/100).
- App-group member picker: debounced server-side search.
- Icon upload accepts `image/svg+xml`, byte-sniffed so an HTML document can't be
  smuggled behind the content-type.

### Fixed
- App-group picker/member list silently truncated at 100 (page_size:200 request vs a
  100 server cap) — members now come from the relation endpoint.

## [1.7.2] — 2026-07-21

### Changed
- Portal navbar decluttered.

### Fixed
- Stale-SPA caching fixed at the nginx + Helm layer (index.html no-cache, hashed
  assets immutable).

## [1.7.1] — 2026-07-21

### Added
- **Global Single-Logout.** Logging out of the portal or console now fans SLO out to
  every downstream SP the user holds a session with — previously only MXID's own
  sessions were destroyed and SP sessions survived.
  - SAML `SessionIndexStore` and CAS `ServiceRegistry` gain a per-user app index
    (`AppsForUser`) for reverse lookup.
  - `authn` logout gains a `SetGlobalLogout` seam, invoked before local session
    teardown (OIDC fan-out needs the live SSO session to enumerate RPs).
  - Best-effort, non-blocking: each protocol reads its index synchronously and POSTs
    to SPs on detached goroutines.

## [1.7.0] — 2026-07-21

### Added
- **Dual login for external users** — external-IdP (Lark) users can set an initial
  local password via portal self-service (no old password required) or console admin;
  guarded by `HasUsablePassword` so it can never bypass the old-password check.
- **Email as a login identifier** alongside username (username matched first; email
  fallback only when the input looks like one), preserving the anti-enumeration
  timing equalizer.
- **SAML/CAS group dispatch** — opt-in per-app `group_attribute` emits the user's
  group codes as a multi-value attribute (empty = not sent); `app_roles` unaffected.
- Console surfaces `role_attribute` + `group_attribute` in the SAML/CAS protocol
  config UI (`role_attribute` was backend-only).

### Fixed
- Admin user-list search did nothing (frontend sent `keyword`, backend bound `search`).

## [1.6.4] — 2026-07-20

### Fixed
- Portal password change, error surfacing, HTTPS/CSRF hardening, console UX.

## [1.6.3] — 2026-07-20

### Fixed
- CAS login falls back to the portal session, breaking an SLO redirect loop.

## [1.6.2] — 2026-07-20

### Added
- Admin UI to set a form app's shared credential. (EE: `GET` shared-credential
  status endpoint.)

## [1.6.1] — 2026-07-17

### Added
- Configure a form app in one step via the extension's Record mode.
  (EE: endpoint accepting the captured descriptor from the extension.)

## [1.6.0] — 2026-07-14

### Added
- External-IdP MFA-challenge seam + portal verify flow for federated login.
  (EE: enforce the MFA challenge on federated login.)
- i18n for protocol-config, provider and timezone descriptors.

### Fixed
- Portal: uniform app-card height; localized form-fill/link protocol badge; long app
  names no longer truncated.
- Duplicate `common.close` i18n key broke the web build.

## [1.5.2] — 2026-07-14

### Fixed
- A valid EE license now grants every *implemented* feature — new features light up
  on binary upgrade with no re-issued license.

## [1.5.1] — 2026-07-14

### Added
- Console browser-extension rollout page for form-fill SSO.

## [1.5.0] — 2026-07-14

### Added
- **Form-fill SSO (SWA).** Vault seams in CE + the MV3 browser extension for
  auto-login into password-only web apps. (EE: credential vault + browser-extension
  token binding, feature key `form_fill`.)

## [1.4.1] — 2026-07-13

### Fixed
- Last-login stamping, app-icon upload authz, custom environment labels.
  (EE: stamp last-login on federated logins.)

## [1.4.0] — 2026-07-10

### Added
- Per-app environment label with portal environment sub-grouping.

### Fixed
- Missing `ON DELETE CASCADE` healed on app child tables.
- Portal consent app icon rendered via the shared `AppIcon`.

## [1.3.1] — 2026-07-10

### Fixed
- OIDC honours the runtime issuer override.
- OIDC/SAML `logout_token` `sub` resolved via the app's subject strategy.

## [1.3.0] — 2026-07-10

### Added
- Observability, CI hardening, shared-UI a11y.

### Security
- P0/P1/P2 hardening pass + CAS proxy authentication.

### Changed
- Console modals migrated to the shared `Modal` primitive.

### Fixed
- Domain error leakage; frontend 40003 error-code collision.

## [1.2.3] — 2026-07-10

### Added
- Periodic dynamic-group reconcile sweeper.

### Security
- All sessions revoked when a user is deleted.

### Fixed
- Deleting a user strips their memberships, bindings and grants.
- Dynamic groups resync on user attribute changes.
- Config entities hard-deleted so cascades fire; orphans removed.
- Stopped swallowing errors that hid failures.

## [1.2.2] — 2026-07-09

### Fixed
- GORM scan structs tagged so they survive garble field obfuscation.
  (EE: pre-push garble-safety gate; `login.success` published on federated login.)

## [1.2.1] — 2026-07-09

### Added
- TOTP code auto-submits at 6 digits.

### Fixed
- Dynamic subtree groups resync when an org is re-parented.
- Orphaned access policies purged when a subject group/org/role is deleted.
- Step-up MFA modal renders above the triggering dialog.

## [1.2.0] — 2026-07-09

### Changed
- **Migrated to `zitadel/oidc` v3 as the sole OIDC provider**, at full parity.
  Consequences: `response_type` is `code` only (implicit + hybrid dropped, OAuth 2.1),
  `offline_access` is required to be issued a refresh token, `client_secret_jwt` is
  unsupported (secrets are bcrypt-hashed one-way — use `private_key_jwt`).

### Added
- Admin-configurable per-user request rate limit (SSE streams exempt).
- OIDC integration overview + Jenkins guide under `docs/integrations/`.

### Fixed
- OIDC claims resolved cross-tenant at the token endpoint.
- Live dynamic-group sync, user org visibility, tenant scoping.
- Health-check probe logs muted in the web nginx ConfigMap.

## [1.1.4] — 2026-07-08

### Added
- Helm: independent per-component image tags (`image.backendTag` / `image.webTag`).
- Friendly console message when external-IdP login is denied.

### Changed
- Release images published to the repo owner's GHCR namespace (CE + EE).

### Fixed
- nginx mutes health-check probe access logs (GoogleHC / kube-probe).

## [1.1.3] — 2026-07-08

### Added
- Super-admin managed through the Super Admin role; member names shown.
- Dev-EE hot-reload compose target.
- (EE) SCIM 2.0 L2 offboarding deprovision connector; external-idp + ee/info console
  routes declared to the deny-by-default gateway.

### Security
- Mandatory MFA enrollment enforced on **every** login path.

### Fixed
- `external_idp (tenant_id, code)` uniqueness made soft-delete-aware.
- L2 authz cache purged on coarse invalidation so role-member adds apply at once.

## [1.1.2] — 2026-07-07

### Added
- `MXID_SERVER_TRUSTED_PROXIES` env + chart `config.trustedProxies`.
- Helm: optional GKE `HealthCheckPolicy` pointing the LB health check at `/health`.
- Helm: configurable `image.registry` for private / Harbor mirrors (air-gapped).

## [1.1.1] — 2026-07-06

### Added
- Dependency-aware **`/readyz`** readiness probe (pings DB + Redis, 503 on failure)
  and a `wait-for-deps` initContainer. Liveness stays on `/health`.

## [1.1.0] — 2026-07-06

### Added
- **Tamper-proof audit (Phases 1–5).**
  - GORM capture plugin (create/update/delete with before-snapshot + SET delta),
    `Audited` marker interface, resource detector, redaction; write aborts if capture
    fails. `audit_pending` → single-writer chainer → append-only `audit_entry`
    (DB trigger + `bytea` payload) → `chain_head`. Canonical JSON + HMAC entry hash.
  - Merkle roots per segment, range-bound **Ed25519** anchors persisted to an
    `AnchorSink` (local `FileSink`), background anchorer loop.
  - Verification: `verify-audit` CLI (chain + anchor status + sink-diff, detects
    deleted anchor rows via contiguity + from_seq reconciliation), multi-key anchor
    registry surviving key rotation (retired pubkeys config).
  - **Third-party-verifiable export**: `audit-export` builds a bundle, offline
    `verify-export` proves it with the public key alone.
  - Auth / sensitive-read app events bridged into the chain with redacted detail.
- **JIT privileged access** (EE-gated via `conditional_access`): time-bound role and
  app-role bindings, eligibility config, self-service request → approval → auto-expire.
  Separation-of-duties + per-eligibility approver scoping + `require_stepup` on
  approve; background expiry sweeper; console approvals + eligibility pages, portal
  request page; expired/revoked bindings excluded from both console RBAC and SSO
  `app_roles`.
  - **Downstream grant termination** on expire/revoke, composite across protocols:
    OIDC per-app back-channel logout, SAML IdP-initiated SLO (per-user-per-app session
    index), CAS Single Logout (per-user service-ticket registry).
- **Offboarding.** L1 one-click access cutoff (disable + kill all sessions +
  back-channel logout fan-out + audit). L3 review checklist of the user's app
  footprint. L3 signed (HMAC-SHA256) webhook to customer IT/HR/ITSM. L2 downstream
  SCIM deprovision seam (per-app provisioning config UI in CE; connector in EE).
- **Transactional outbox** (`internal/outbox`, `mxid_outbox`): `EnqueueTx` in the same
  transaction as the state change; worker claims with `FOR UPDATE SKIP LOCKED`
  (replica-safe, no leader election), backoff + dead-letter.
- **App template marketplace** (CE): embedded catalog (DingTalk, WeCom, GitLab,
  Grafana, Jenkins, Jira, Confluence, JumpServer) + create-app template picker with
  brand icons.
- **HA multi-replica hardening**: leader election for single-writer jobs, cross-pod
  cache invalidation, upgrade-safe migrations, graceful shutdown of background workers.
- **SP-initiated login confirmation** + per-app JIT roles across OIDC/SAML/CAS.
- Registry seam extended with `OutboxRegister` + `ProvisioningConfig` hooks so EE
  features can bind durable handlers and read CE-stored config.
- Inline base64 avatars with crop upload; user-list avatar/MFA badges.
- Design system: token-driven theming + dark mode + shared component kit; console
  shell, dashboard, users, audit, tenants, approvals, offboarding, idps rebuilt on it.
- Observability: `traceId` in responses + `request_id` propagation.
- Error-code registry + `response.MapError`.
- AGPL v3.0 declared; README rewritten; SECURITY policy; `.github/` issue + PR
  templates; `docs/DEPLOYMENT.md`, `docs/ARCHITECTURE.md`.

### Security
- Hard deny-by-default console authz gateway enabled.
- bcrypt cost raised to 12 (enumeration equalizer kept in sync).
- SAML SP-initiated `LogoutRequest` signature verified; non-S256 PKCE rejected.
- Admin per-user session endpoints secured; settings writes require `settings.manage`;
  branding `login_footer_html` sanitized; app provisioning config tenant-scoped.
- Stopped leaking gin binding-error detail / raw error text / sensitive query params
  and SQL literals; RP `jwks_uri` and SMS provider response bodies capped; all SMS
  providers routed through timeout-bounded `safehttp`.
- Release mode requires `allowed_origins` + a non-localhost issuer.
- Dependency bumps: `jackc/pgx/v5` v5.9.2, x/crypto, x/net, x/image, edwards25519,
  `@babel/core` 7.29.7 (GHSA-4x5r-pxfx-6jf8).

### Fixed
- Audit: `app.*` events record their resource id (was always blank), the
  changed-field list on updates, and the failure reason on `login.failed`; the
  api.* catch-all carries the route's `:id`; console audit log gains an api-noise
  filter. Closed blind spots: app access grants, signing certs, app roles, role
  bindings and access policies emit attributed domain events.
- A disabled account entering the correct password is told the account is disabled
  (403) instead of "wrong password" — without leaking account state to enumerators.
- OIDC refresh grant rejects disabled users (a live refresh token no longer mints
  access tokens after the account is disabled).
- Console org members resolve by id instead of a broken list filter.
- Domain not-found / conflict / validation errors map to 4xx, not 500; 500 causes are
  logged instead of swallowed.
- Username uniqueness made soft-delete-aware; group member-count N+1 fixed;
  user create + detail + password-history now one transaction.
- Idempotent TOTP setup; step-up-fresh on enroll; distinct replay error.
- Helm production hardening (non-root backend, secret guardrail, prereq notes);
  canonical external URLs wired so prod stops issuing under the placeholder.

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
- OIDC 1.0: Authorization Code + PKCE, Refresh, Implicit, Hybrid, Client Credentials
  *(Implicit + Hybrid removed in 1.2.0 — OAuth 2.1 alignment)*. Discovery, JWKS,
  RP-Initiated + Back-channel Logout. Per-app claim mappers.
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

[Unreleased]: https://github.com/imkerbos/mxid/compare/v1.8.0...HEAD
[1.8.0]: https://github.com/imkerbos/mxid/compare/v1.7.4...v1.8.0
[1.7.4]: https://github.com/imkerbos/mxid/compare/v1.7.3...v1.7.4
[1.7.3]: https://github.com/imkerbos/mxid/compare/v1.7.2...v1.7.3
[1.7.2]: https://github.com/imkerbos/mxid/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/imkerbos/mxid/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/imkerbos/mxid/compare/v1.6.4...v1.7.0
[1.6.4]: https://github.com/imkerbos/mxid/compare/v1.6.3...v1.6.4
[1.6.3]: https://github.com/imkerbos/mxid/compare/v1.6.2...v1.6.3
[1.6.2]: https://github.com/imkerbos/mxid/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/imkerbos/mxid/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/imkerbos/mxid/compare/v1.5.2...v1.6.0
[1.5.2]: https://github.com/imkerbos/mxid/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/imkerbos/mxid/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/imkerbos/mxid/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/imkerbos/mxid/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/imkerbos/mxid/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/imkerbos/mxid/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/imkerbos/mxid/compare/v1.2.3...v1.3.0
[1.2.3]: https://github.com/imkerbos/mxid/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/imkerbos/mxid/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/imkerbos/mxid/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/imkerbos/mxid/compare/v1.1.4...v1.2.0
[1.1.4]: https://github.com/imkerbos/mxid/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/imkerbos/mxid/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/imkerbos/mxid/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/imkerbos/mxid/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/imkerbos/mxid/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/imkerbos/mxid/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/imkerbos/mxid/releases/tag/v0.1.0
