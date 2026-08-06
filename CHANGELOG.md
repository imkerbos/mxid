# Changelog

All notable changes to MXID are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Creating a dynamic user group no longer fails, and no longer takes the pod
  down.** The audit capture plugin read the primary key straight off the
  statement value; on a batch insert that value is a slice, and reflect panics
  reaching for a struct field on it. Adding members to a dynamic group is
  exactly one batch insert, so every rule sync panicked — as a 500 with no
  usable message inside a request, and as a dead process on the startup
  reconcile worker, which put the pod in CrashLoopBackOff until the group was
  deleted by hand, because the data was still there on each restart. The
  sibling function three lines above already handled the slice; this one did
  not.

### Fixed
- A server error now tells the user something they can act on. A 500 surfaced as
  axios' own 'Request failed with status code 500' — neither what failed nor
  what to do — because the request id the server stamps on every response was
  dropped on the way to the toast. The message now carries it, so an operator can
  find the actual cause in the server log. A response with no parseable body at
  all (gateway page, dropped connection) is reported as a server-side failure
  rather than as an axios string.

### Fixed
- **An account forced to change its password could not change it.** With TOTP
  enrolled, the change-password route demanded a code unconditionally — ignoring
  that the session had just passed MFA at sign-in. Both fall inside the same
  30-second TOTP window, so the only code the user has is the one they just
  spent, and it comes back rejected as a replay. Every other route stays closed
  until the change succeeds, so the seeded administrator (and anyone an admin had
  just reset) was locked out of the installation by following the product own
  instructions. The route now honours the same sudo window as every other
  high-risk operation.
- The forced-change screen showed raw i18n keys (`account.password.forceTitle`
  and seven others). The locale namespace is `account.pwd`; the component asked
  for `account.password`.
- The forced-change screen had nowhere to enter a TOTP code, so once the sudo
  window did expire there was no way to satisfy the demand. It now reveals a code
  field when the server asks for one.

## [1.8.4] — 2026-08-06

### Fixed
- Two error sentinels that nothing ever returned are gone (`app.ErrAccountNotFound`,
  `group.ErrGroupNotDynamic`). Both were declared and bound to a business code,
  so they held a number and implied an error path that did not exist.
- **No goroutine can take the process down any more.** Fixing `SpawnWorker`
  covered its twelve callers; a sweep found **nine more** started with a bare
  `go func` — the OIDC and CAS logout fan-outs, four Redis pub/sub loops, the
  JIT sweeper, the dlock campaign and the HTTP server itself. Every one of them
  had the same failure mode. They now go through `pkg/safego`, and a guard test
  fails the build on a new bare goroutine, because the rule is only worth as
  much as its weakest call site: the outage came from the one goroutine written
  before the rule existed, and nine more were found in code by people who knew it.
- **A panicking background worker no longer takes the whole process down.**
  `SpawnWorker` ran the job without a recover, and an unrecovered panic in any
  goroutine kills the program — so one bad row could stop every login in the
  deployment. It was not transient either: the row survives the restart, the
  reconcile worker runs again, and the pod sits in CrashLoopBackOff until
  someone finds and deletes the data. A panic is now contained, logged with its
  stack, and costs one background job instead of the service.
- The dynamic-group reconcile no longer scans the whole group table. It filters
  on `(tenant_id, type)` while the only index was `UNIQUE (tenant_id, code)`
  (migration 000067).
- Creating a user group cannot fire twice from one submit. The in-flight guard
  was React state, so a second click in the window before the re-render went
  through and conflicted with the row the first was still creating; it is a ref
  now, which is written synchronously.

### Added
- `mxid-server admin reset-password` — the break-glass path for a forgotten
  administrator password when no second super-admin can reset it. Until now the
  only recovery was hand-writing a bcrypt hash into `mxid_user`, which bypassed
  the password policy, the reuse history, the session revocation and the audit
  trail alike, and required handing out database access. The subcommand goes
  through the same service method the console uses, forces a password change at
  first sign-in, optionally unlocks the account (`-unlock`), and records the
  actor as `cli` so the change is distinguishable from a console reset. There
  is no `-password` flag by design — the password is prompted for, piped in, or
  generated. See *Administrator password recovery* in the deployment guide.

### Fixed
- The API-token garbage collector no longer scans the whole table. It deleted on
  `expires_at` OR `revoked_at`, and neither column was indexed, so the periodic
  purge was a sequential scan that grew with every token ever issued. The query
  is now two statements, each matching a partial index (migration 000066).
- A duplicate user-group or organization code is reported as a conflict instead
  of a server error. The uniqueness violation reached the console as a bare 500
  `failed to create user group`, which reads as a server fault rather than
  `pick another code` — so an administrator retried, every retry collided with
  the row the first attempt had already created, and the log filled with 500s
  for a group that existed all along. Both domains now return 40906 and the SPA
  renders one translated sentence for it.

## [1.8.3] — 2026-08-05

### Fixed
- **A fresh release install is no longer locked out of itself.** v1.8.2 locked
  the seeded `admin` account when `MXID_BOOTSTRAP_ADMIN_PASSWORD` was unset. On a
  first deployment `admin` is the only account, so that left nobody able to sign
  in — and the documented way back in, setting the variable and restarting, did
  not exist under Helm, whose chart never exposed it. The account now stays
  usable and owes a password change instead: a session opened with the published
  password reaches nothing but the change-password endpoint, because
  `PwdGateMiddleware` blocks every other route while `must_change_pwd` stands.
  **Upgrading is enough to recover an install v1.8.2 locked out** — the same
  startup pass releases the account, with no operator action.
- The Helm chart now exposes `secrets.bootstrapAdminPassword`
  (`MXID_BOOTSTRAP_ADMIN_PASSWORD`), so the supported way to set the initial
  administrator password exists for Helm deployments and not only for Compose.
- The web image builds reproducibly. `corepack enable` had no version to
  resolve, so every build downloaded whatever pnpm was newest at that moment and
  the same tag built differently from one week to the next. `web/package.json`
  now pins `packageManager`, which corepack honours everywhere it runs: the
  release image, the dev image and the dev-compose vite containers.

## [1.8.2] — 2026-08-04

**Security release. Upgrade if you run v1.8.1 or earlier.** Every install before
this one starts with a super-admin password that is written in plaintext in a
migration file in this public repository, and nothing forced it to be changed.
See the first entry under Security.

### Added
- `scripts/backup.sh` (`make backup`, `make backup-verify`) — dump, verify and
  restore. `verify` restores the file into a throwaway database and checks the
  schema version and core tables, because a backup nobody has restored is a hope
  rather than a backup. It also states what a dump does NOT contain: the
  encryption key (secrets restore as unreadable bytes without it), Redis
  sessions, and the EE licence fingerprint, which a logical restore into a new
  cluster invalidates.
- Audit records can be mirrored to a syslog collector as they are written
  (`audit.forward.addr`, RFC 5424 over UDP / TCP / TCP+TLS). The tamper-evident
  chain proves nobody rewrote history; it does nothing about someone with
  database access dropping the table, and an off-host copy is what survives
  that. Forwarding NEVER blocks the audit write — it runs on a path synchronous
  with every write API, so the queue is bounded and overflow is dropped and
  counted (`mxid_audit_forward_total`) rather than waited on. A stalled
  collector costs you mirror completeness, never availability.
- The audit alert webhook now actually sends. `alert_webhook_url` and
  `alert_on_event_types` have been in the console since the settings existed and
  nothing read them: an administrator filled the field in, got a "saved" toast,
  and no alert would ever have been delivered. Selected events are now POSTed as
  JSON through the transactional outbox, so an alert about a security event
  survives a restart, and through `pkg/safehttp`, because an administrator-
  supplied URL is otherwise an SSRF primitive. Repeats of one event type are
  held for five minutes and the next alert reports how many it stands for —
  ten thousand failed logins is one incident, and a channel that floods gets
  muted.

### Removed
- The "high-risk recipients" field is gone from the audit-policy page. Nothing
  delivered to an email address or a phone number, so it accepted a value, said
  "saved", and did nothing. It returns when a channel exists behind it.

### Security
- **A release deployment no longer serves with the seeded administrator
  password.** Migration 000009 seeds `admin` with a password written in
  plaintext in the migration itself, in a public repository, and nothing changed
  it, warned about it, or forced it to be changed — so every production install
  started with a super-admin credential that any reader of the source already
  had. Release builds now take the password from
  `MXID_BOOTSTRAP_ADMIN_PASSWORD`, and **lock the account if it is unset**.
  Locking rather than merely gating is the point: a gated session can still
  reach the change-password endpoint, so anyone who knew the published password
  could have taken the account over instead of being kept out. Other
  administrators are unaffected and one restart with the variable set restores
  it. Development builds are untouched.
- **`must_change_pwd` is enforced.** It was written by every administrative
  password reset and documented as forcing the user to choose a new password at
  their next sign-in; the only thing in the codebase that read it was a badge on
  the console user-detail page. An administrator resetting a compromised
  account's password believed they had forced a change that never happened. A
  session that owes one now reaches nothing but the change-password endpoint,
  decided at session creation so every login path is covered — password, SMS,
  magic link and external IdP alike — and self-healing once the password is
  changed.
- The server container runs as an unprivileged user. The Helm chart already
  applied `runAsNonRoot`, but the image had no `USER` and the compose path — the
  one the deployment guide leads with — ran the server as root. The image now
  ships a uid-1000 user with a read-only `/app`, and the compose service drops
  all capabilities and mounts the root filesystem read-only.
- Locking or disabling an account now cuts the sessions it already holds.
  `AuthMiddleware` resolves a session without re-reading the user's status, so
  disabling a leaver did not actually stop them — they kept working until the
  session idled out. Deletion and admin password reset already revoked; lock and
  disable did not. A lockout from the brute-force limiter deliberately does NOT
  revoke: an attacker who could trigger it would otherwise be able to throw
  someone out of a live session by failing logins against their username.
- Session revocation now covers the protocol namespace — the shared SSO session
  — alongside the console and portal ones. A deleted user kept a live SSO
  session and could go on completing OIDC/SAML/CAS sign-ins to downstream
  applications, which is the access revocation exists to cut. The offboarding
  flow already revoked all three; the event-driven paths revoked two.
- Session revocation no longer depends on winning a race with the HTTP response.
  Event handlers run on their own goroutine, so the request context that
  published the event was usually already cancelled by the time the handler
  reached Redis; go-redis honours cancellation and the error was discarded, so
  the revocation silently did not happen. Confirmed by test: under a cancelled
  context, every session in all three namespaces survived.
- Audit retention can no longer be shortened past a floor the deployment sets
  (`audit.min_retention_days`, default 180 days). Retention is runtime-editable
  in the console and had no validation at all, so anyone with `settings.manage`
  could quietly reduce it to a week — destroying evidence in a way that leaves
  no evidence. A stored value below the floor is raised to it when the purge
  reads the policy, so introducing or raising a floor never deletes anything it
  would not have deleted before.

### Fixed
- Audit entries for a lock or a status change now record the account's new
  status. The detail allow-list dropped the field, so the log said a user was
  updated without saying what they were updated to.

## [1.8.1] — 2026-08-04

### Changed
- Console and portal forms now use one label style throughout. 57 hand-rolled
  label/control/hint blocks moved onto the shared `Field` primitive, which draws
  the required marker, associates the label with its control and carries
  `aria-invalid` / `aria-describedby` — none of which the hand-rolled blocks had.
  Labels are a step larger and darker than before, matching the forms that
  already used the primitive. The dark sign-in screens keep their own labels:
  they are a different surface, and `Field`'s light-surface styling would break
  them.
- `make seed-demo` now gives every demo app a description and enrols a second
  factor for most demo users. Without them the console and portal read
  "No description" on every card and the dashboard reported "MFA coverage 0.0%",
  which made a populated demo look like an empty one.
- The default subject strategy is now chosen per protocol: OIDC keeps
  `persistent_id`, while SAML and CAS default to the username. One shared
  default served all three and the OIDC-shaped answer won, so a CAS app created
  through the console emitted a snowflake id as `cas:user` — and JumpServer,
  Redmine and Zabbix key local accounts off that value. Existing apps are
  untouched; this only changes what a newly created app starts with.
- The account page's form labels now match the rest of the console. It declared
  a private copy of the shared `Field` primitive that shadowed the import, so its
  labels were styled differently and it had no slot for a validation message. A
  second unused copy (`FormField`) has been removed as well.

### Security
- `brace-expansion` pinned to a patched version (GHSA-mh99-v99m-4gvg). It is a
  dev-only transitive dependency so nothing reached a user, but a lockfile
  carrying a known-vulnerable version shows up on every scan.
- Failed logins against a username that matches no account now count towards the
  per-IP brute-force limit. They were skipped entirely, so a scripted scan over
  invented usernames incremented nothing: no captcha was ever demanded and no IP
  lock ever tripped, however many attempts it made.
- A mistyped SAML `sp_cert` is now rejected when the SP descriptor is built.
  Most short strings are valid base64, so garbage decoded cleanly and only
  surfaced later as an opaque signature failure on the SP's next signed
  AuthnRequest.
- External-IdP providers (Lark/Feishu, Teams, GitHub) now make their OAuth calls
  through the SSRF-guarded client instead of a bare HTTP client, so a redirect
  from a compromised IdP cannot walk the request onto an internal address with
  the app's bearer token attached. (EE) **Deployment note:** that client ignores
  `HTTPS_PROXY`, as every other outbound fetch already did, so a network that
  needs an egress proxy to reach Lark/Feishu/Teams must allow those hosts
  directly. See *Outbound requests do not use an egress proxy* in
  `docs/DEPLOYMENT.md`.
- Five error responses showed the user a message about something else. The SPA
  replaces the server message with a fixed translated sentence for certain
  numeric codes, and those codes had been reused: a bad dynamic-group rule and an
  invalid access-eligibility body both rendered as "this app has no login URL", a
  missing captcha rendered as "that code was just used", and a disabled login
  method and a missing TOTP code both rendered as "that password matches a recent
  one". All five now carry codes of their own.
- Access-policy label resolvers now filter by tenant, honouring the shared-app
  rule: a globally shared app has no tenant, so scoping it with a plain equality
  would have hidden every shared app's name. They query with `.Table()`
  into anonymous scan structs, which the tenantscope plugin cannot see, so any id
  from any tenant resolved to a name — a cross-tenant label oracle. Request-bound
  callers now carry the predicate; the tenant-less paths (logout terminators,
  background jobs) are unchanged, since they have no tenant to filter by.

### Fixed
- `make smoke` has not worked since v1.0.0. It sends no `Origin` header, which
  the CSRF middleware requires, so it died at the first login with a bare 403 —
  unnoticed because CI never ran it. Its portal probe also signed in as `admin`,
  who administers apps rather than being granted any, so the last check failed
  against a healthy system. Both fixed.
- The example env files pinned `MXID_TAG=v0.1.0`, a tag that is no longer
  published. Since deploying starts with `cp .env.example .env`, the first thing
  a new user hit was an image pull failure. Now pinned to the current release,
  with a check that fails the build if it goes stale again.
- Creating an organization with a hyphen in its code returned a bare 500. The
  code becomes a PostgreSQL ltree label, which allows only letters, digits and
  underscore — and the console's own hint recommended "lowercase + hyphens" and
  used `tech-team` as the worked example, so an admin following the interface was
  guaranteed to hit it. The code is now validated with a message naming the rule,
  and the hint recommends what actually works.
- A portal app card with an unbreakable name (no spaces) rendered it as one long
  line that escaped the card instead of ellipsing, pushing the protocol badge
  underneath the launch icon. Names and descriptions now break, and the badge
  keeps clear of the icon.
- The login captcha could not appear, on either screen, for two separate
  reasons. Both branched on the old numeric code for "captcha required", and
  both read that code off the wrong property of the rejected request: the API
  client rejects with an error carrying a numeric `code` and no `response`, so
  the message lookup (which falls back correctly) showed the right text while
  the branch that reveals the widget got `undefined` and never fired. A user who
  tripped the captcha threshold could not log in at all. Both fixed, and the
  codes are now named constants read through one shared helper.
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
  without a history row (making it reusable past the reuse policy). The reset
  also refreshes the password-expiry clock and clears a stale must-change flag,
  so resetting an expired account actually lets its owner back in.
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

[Unreleased]: https://github.com/imkerbos/mxid/compare/v1.8.4...HEAD
[1.8.4]: https://github.com/imkerbos/mxid/compare/v1.8.3...v1.8.4
[1.8.3]: https://github.com/imkerbos/mxid/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/imkerbos/mxid/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/imkerbos/mxid/compare/v1.8.0...v1.8.1
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
