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
app/                         real entrypoint: app.Run() + adapter glue (~1300 LOC god-file, intentional per
                             project memory — importable so the EE module can reuse it)
cmd/server/                  thin main() shim that calls app.Run()
internal/
├── bootstrap/               viper config, gorm wiring, migrations, snowflake IDs, router (+/readyz), logger
├── domain/                  one package per business capability
│   ├── user/                local accounts, MFA, password history
│   ├── tenant/              the single default tenant record (see "Tenant column" below)
│   ├── app/                 SP registration + protocol_config + access policy
│   ├── authn/               login orchestration, captcha, MFA challenge, login policy, global logout seam
│   ├── audit/               tamper-proof audit chain (capture plugin → chainer → anchors, see below)
│   ├── setting/             hot-reload runtime config (the central knob)
│   ├── consent/             OIDC scope consent grants
│   ├── appaccess/           per-app allow/deny rules
│   ├── approle/             per-app role bindings
│   ├── access/              JIT privileged access (eligibility → request → approval → binding)
│   ├── conditionalaccess/   conditional-access policies (EE runtime-gated)
│   ├── auditalert/          turns selected audit events into outbound alerts (outbox-backed, cooled down)
│   ├── offboarding/         leaver workflow: L1 SSO cut / L3 review checklist / L2 deprovision seam
│   ├── provisioning/        per-app outbound-provisioning config (SCIM connector config; connector is EE)
│   ├── oidckey/             provider-level OIDC signing keyset with active/passive rotation
│   ├── platformconfig/      pre-tenant config: license token, install fingerprint (see below)
│   ├── dashboard/           console dashboard aggregate queries
│   ├── apitoken/            headless API tokens
│   ├── org/                 org tree (departments)
│   ├── group/               static + dynamic user groups
│   ├── permission/          role-based authz primitive
│   └── upload/              binary asset store (icons / logos → mxid_upload, bytea, ≤2 MB)
├── protocol/                stateless protocol handlers
│   ├── oidcop/              OIDC provider built on zitadel/oidc v3 (authorize, token, userinfo,
│   │                        introspect, revoke, jwks, discovery)
│   ├── oidclogout/          OIDC RP-initiated end_session + back-channel logout dispatch
│   ├── saml/                metadata, sso (POST + redirect bindings), slo, per-user SessionIndexStore
│   ├── cas/                 login, validate, serviceValidate, p3/serviceValidate, proxy, logout
│   └── resolver/            AppResolver / IdentityResolver / SessionResolver interfaces — protocols
│                            read domain state without importing domain packages
├── gateway/                 HTTP boundary
│   ├── console/             admin REST surface (CRUD over domain)
│   └── portal/              end-user REST + SSO bounce + magic-link / SMS / password-reset
├── middleware/              cors, csrf, security headers, request-id, structured logger,
│                            rate-limit, feature gate (RequireFeature), tenant override
└── outbox/                  transactional outbox: durable at-least-once side-effect delivery
pkg/                         ~30 reusable libs; the load-bearing ones:
├── safehttp/                SSRF-guarded HTTP client — MANDATORY for all outbound requests
├── saferedirect/            fail-closed validators for return_to / RelayState / CAS service URLs
├── tenantscope/             gorm plugin: automatic fail-closed tenant row scoping
├── tenantctx/               effective tenant_id from gin.Context
├── authz/                   role + scope check primitives (authz.Require / authz.Protect)
├── dlock/                   Postgres advisory-lock leader election for single-writer jobs
├── ratelimit/               Redis-backed brute-force limiter keyed by (purpose, identifier)
├── secure/                  wrapper types that suppress secrets in String()/encoding
├── crypto/                  AES-GCM, bcrypt, HMAC, Ed25519 helpers
├── errcode/                 single registry: domain sentinel → (HTTP status, stable numeric code)
├── dberr/                   persistence error sentinels (not-found etc.) without gorm imports
├── response/                API envelope + MapError / InternalError conventions
├── auditctx/                request-scoped actor identity carried via context for audit writes
├── auditsink/               off-host audit mirror (RFC 5424 syslog); NEVER blocks the audit write
├── mask/                    PII redaction helpers for API responses
├── ssoflow/                 one-time SSO login-confirmation tokens
├── metrics/                 Prometheus RED metrics + /metrics handler
├── geoip/                   IP → city/country for the audit pipeline
├── event/                   in-process pub-sub bus (at-most-once — see outbox)
├── session/                 redis-backed session manager
├── urlswap/                 canonical-URL resolution (admin setting → defaults → request-host swap)
├── mailer/ sms/ snowflake/  SMTP + templates, SMS senders, globally unique IDs
├── updatecheck/ version/    release update check, build-time identity
└── ee/                      license verification, feature gate, EE registry seam (see Editions)
```

Note: `externalidp` is **not** a CE package. External IdP login (Lark / GitHub / Teams …) is a
code-separated EE feature living in `mxid-ee/features/externalidp`; the CE binary contains none of it.

### Why this shape

- **Domain packages own their model + service + repository**. They expose narrow interfaces. Gateways import domain services; domain packages never import gateways.
- **Protocol handlers are stateless** and read state through `resolver` interfaces. Adding a new protocol (e.g. WS-Federation) means a new `internal/protocol/wsfed/` package and a few adapter functions wired in `app/run.go`.
- **Setting domain is the runtime config bus**. Every operationally-adjustable knob lives here. Handlers read settings via per-tenant accessors. Admin UI is a CRUD over the same shape. No restart required for any operational change.
- **`pkg/` is for libraries that don't know about MXID's business model**. Anything in `pkg/` could theoretically be open-sourced as a separate dependency.
- **`upload` domain keeps binary assets in the database** (`mxid_upload`, `bytea`). Served with `ETag` + `Cache-Control: immutable` so browsers get one-hit caching without a CDN. The side-effect: the backend carries zero local file state → no PVC needed on Kubernetes, no asset loss on container restart, and all replicas are consistent.

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

## OIDC engine

Since v1.2.0 the OIDC provider is `github.com/zitadel/oidc/v3` — the sole engine (the
self-built provider was deleted). `internal/protocol/oidcop` wraps it with MXID storage,
discovery filtering, and rate limiting. Capability posture (OAuth 2.1 alignment):

- `response_type=code` only — implicit and hybrid flows are removed, and the discovery
  document is filtered so they are never advertised.
- Refresh tokens require the `offline_access` scope.
- `client_secret_jwt` is unsupported by design: client secrets are stored bcrypt-hashed,
  so the raw secret needed to HMAC a JWT never exists server-side. Use `private_key_jwt`
  for asymmetric client authentication.

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
| `ExternalURLs` | every protocol handler via `urlswap.Resolve`; IdP callback / post-login redirect URLs resolved at runtime from this setting (no env required) | Settings → External URLs |

Sensitive fields (SMTP password, SMS secret) are AES-encrypted with the master KEK (`MXID_CRYPTO_KEY_ENCRYPTION_KEY`) at write time, decrypted on read. The encryption pipeline is in `setting.Service` — adding a new sensitive field requires only registering it in `sensitiveFields`.

## Platform-level config — physical isolation from tenant settings

Certain records must be read **before** a tenant context is known — most notably the license token and the installation fingerprint (`install_uuid`). These live in a dedicated table `mxid_platform_config` (domain `platformconfig`) rather than in the tenant-scoped `mxid_setting` table. The reason is structural: the GORM `tenantscope` plugin is fail-closed by design; if a query runs without a tenant scope it silently returns no rows instead of the intended row. Placing license / fingerprint data in `mxid_setting` would cause them to be invisible at startup time and during login (before any tenant is resolved), leading to silent fallback values and install-fingerprint drift across restarts.

`mxid_platform_config` is **not** partitioned by `tenant_id`. Reads require no scope and are safe at any lifecycle phase.

## Tenant column — schema artefact, not a product capability

MXID is **permanently single-tenant** in both CE and EE. `pkg/ee/license/features.go`
deliberately excludes `FeatureMultiTenant` from `ImplementedFeatures` (and a test asserts no
license ever grants it). The `tenant_id` column and the default tenant row (`id=1`, created on
first migration) are foundational schema artefacts kept for row-scoping discipline — the
`tenantscope` GORM plugin enforces per-row scoping defensively, so any query missing a scope
fails closed (returns nothing) instead of leaking rows.

That fail-closed default caused a category of silent bugs in the `setting` domain — functions like `getRaw` called before or outside a request context (startup, login flow, scheduled tasks) produced empty rows and fell back to defaults. The fix is applied in `setting.getRaw`: when the GORM context carries no tenant scope, the function injects one explicitly using the tenant ID supplied to the call. Queries that already carry a scope (including `cross-tenant` / `system` scopes) are left untouched.

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

## Logout — global teardown + downstream Single Logout

Logout is a cross-surface operation. A single logout request — from console, portal, or a
protocol `end_session` / SLO endpoint — first destroys **all** local state for the user:

1. Console admin session (Redis key)
2. Portal end-user session (Redis key)
3. Active protocol tickets (OIDC refresh tokens, CAS ticket-granting tickets, SAML assertions in flight)

Since v1.7.1 a portal/console logout also fans **Single Logout out to every downstream SP the
user is signed into** — not only when logout arrives through a protocol endpoint:

- Each protocol keeps a per-user app index: the SAML `SessionIndexStore` and the CAS service
  registry both answer `AppsForUser`, and OIDC tracks RPs with back-channel logout configured.
- `authn.Handler.SetGlobalLogout` is the seam: `app/run.go` wires a fan-out function that the
  logout handler invokes **before** local teardown, so downstream notification uses still-valid
  session context.
- Dispatch is best-effort on detached goroutines (OIDC Back-Channel Logout, SAML SLO,
  CAS SLO POSTs) — a slow or dead SP never delays the user's logout response.

## Tamper-proof audit

`internal/domain/audit` implements an evidence-grade pipeline, not just a log table:

1. **Capture** — a GORM plugin snapshots the row *before* a write and records the delta.
   If capture fails, the business write is aborted (`cb.AddError`) — no unaudited mutation.
2. **Staging** — captured events land in `mxid_audit_pending`.
3. **Chaining** — a single-writer chainer (leader-elected via `pkg/dlock`, key
   `KeyAuditChainer`) assigns contiguous sequence numbers and computes
   `HMAC-SHA256(key, seq ‖ prev_hash ‖ canonical_json)` over a frozen canonical payload
   (`MXID_CRYPTO_AUDIT_CHAIN_KEY`; startup fails on a missing/garbage key).
4. **Append-only storage** — entries go to `mxid_audit_entry`, protected by a DB trigger
   (migration 000050) that unconditionally rejects UPDATE/DELETE; `mxid_audit_chain_head`
   tracks each chain tip.
5. **Anchoring** — an anchorer periodically seals the un-anchored tail into a SHA-256 Merkle
   root and signs the (tenant, class, from_seq, to_seq, root) range with Ed25519, recording it
   in `mxid_audit_anchor`. A multi-key anchor registry supports key rotation.

   An anchor serves two purposes, and only one of them is on by default:

   - **Checkpoint (always).** ~375 bytes summarising a range, which is what makes that range
     verifiable — and eventually archivable — without walking the chain from genesis.
   - **External witness (opt-in, `audit.anchor_sink_path`).** Mirroring the signed root
     outside the database is what would catch an operator holding database write access
     rewriting history, since they cannot also rewrite a copy they do not control.

   The witness is **off by default** because the guarantee is real only when the sink is both
   outside the database's blast radius and shared by every replica. Anchors are written by
   whichever replica holds the leader lock, so a per-pod volume scatters them across ordinals
   and makes verification fail depending on which pod runs it — operational failure in place
   of assurance. Turn it on only against a genuinely shared, append-only location.
6. **Verification** — operator subcommands on the server binary: `verify-audit` (walk every
   chain head in place), `audit-export` (build a third-party-verifiable bundle), and
   `verify-export` (offline verification needing only the bundle + trusted public key).

   The binary carries one more, unrelated to audit: `admin reset-password`, the break-glass
   path for a forgotten administrator password with no second super-admin to reset it. It
   goes through the same service method the console uses — so the password policy, the reuse
   history and the session revocation all still apply — forces a change at first sign-in, and
   records the actor as `cli` so an out-of-band reset is distinguishable from a console one.
   Subcommands live on the server binary rather than a separate tool because the situations
   they exist for are the ones where nothing can be built or copied in first.

### Retention on an append-only ledger

`mxid_audit_entry` is append-only and was, by construction, unprunable: with
verification able to start only at seq 1 against the genesis hash, a missing row
was indistinguishable from a deleted one. Removing anything made the chain
unverifiable, so nothing was ever removed and the table grew without bound —
roughly 150k entries a day at 50k business writes, since one interactive login
produces three to five.

A **checkpoint** (`mxid_audit_checkpoint`) removes that constraint. It states,
under Ed25519 signature, that entries up to `pruned_through_seq` existed and
hashed to `prev_hash` — precisely what verification needs to resume mid-chain.
`verify-audit` loads it automatically, so a pruned chain verifies from its floor
instead of reporting a gap, and the pruned range remains attested by its anchor
long after the entries are gone.

Pruning is bounded by two rules:

- **Never past the anchor line.** An anchor is the durable attestation that a
  range existed and what it hashed to; pruning beyond it would destroy entries
  nothing has ever committed to.
- **Never past the caller's cutoff**, so retention policy stays a decision for
  the operator rather than something the mechanism invents.

The checkpoint is written before the entries are deleted, in one transaction. A
crash between them leaves a claimed floor with the entries still present, which
verifies clean; the opposite order would leave an unverifiable chain.

The append-only trigger now distinguishes the two operations rather than
refusing both. **UPDATE is still refused unconditionally** — rewriting history
has no legitimate caller. DELETE passes only when a transaction-local setting
(`mxid.audit_prune`) is on, which cannot leak beyond the transaction that sets
it. This is not a defence against someone with direct database access, who could
set it themselves or drop the trigger; its job is unchanged, which is to stop
the application, an ORM mistake, or a careless operator from destroying
evidence. The alternative — dropping the trigger for the duration of a prune —
would open a window in which the guarantee does not hold at all.

### What the audit chain does and does not prove

Stating this plainly matters more than the machinery, because the layers defend
against different attackers and only some of them are on by default.

| Attacker | Defended by | On by default |
|---|---|---|
| Application bug or careless operator deleting rows | append-only DB trigger (migration 000050) | ✅ |
| Someone who obtains the database (dump, SQL injection, stolen backup) and edits history | HMAC hash chain — recomputing it requires `MXID_CRYPTO_AUDIT_CHAIN_KEY`, which lives in the environment, not the database | ✅ |
| An operator with **both** database write access **and** the chain key, rewriting history end to end | external anchor sink — they cannot also rewrite a copy held outside the database | ❌ opt-in |

So in the default configuration MXID detects tampering by anyone who does not
hold the chain key, and blocks deletion outright. It does **not** claim to prove
that a fully privileged operator did not rewrite history — that requires an
external sink, and a sink is only worth enabling when it genuinely lives outside
the database's trust domain.

Deployments that must make the stronger claim (an external audit obligation, a
contractual tamper-evidence commitment) should enable the sink against shared,
append-only storage, or export signed bundles regularly with `audit-export` —
`verify-export` checks a bundle offline with nothing but the public key, and it
accepts a non-genesis starting sequence, so an exported range stands on its own.

### Partition lifecycle

`mxid_audit_log` is RANGE-partitioned by month. Declarative partitioning is only
half a design on its own: PostgreSQL creates the parent and the first
partitions, then rejects every INSERT once the ranges run out — a hard
`no partition of relation found for row`, which the best-effort audit writer
turns into a silent loss. `pkg/pgpartition` owns the missing half and is driven
by a leader-elected hourly worker (`KeyAuditPartitions`):

- **Rolling pre-creation** keeps the current month plus three ahead provisioned,
  so a wedged scheduler has a quarter of slack before it matters.
- **A DEFAULT backstop** guarantees a write is never lost when pre-creation has
  failed. It is a backstop, not a landing zone: once rows for month M sit in
  DEFAULT, PostgreSQL refuses to create M's partition until they are moved out
  (`Manager.Adopt`, a deliberate manual operation — it holds ACCESS EXCLUSIVE on
  the parent). So `mxid_partition_default_rows > 0` is an alarm for a state that
  blocks its own repair, not a curiosity.
- **Retention drops partitions** rather than deleting rows, which is the reason
  to partition in the first place. Measured on PostgreSQL 15 over 500k rows:
  `DELETE` 169ms with 82MB still resident as dead tuples, `DROP` 5.8ms with the
  space returned. Only wholly-expired partitions are dropped — one straddling
  the cutoff still holds in-policy rows — so the remainder is still deleted by
  row, and retention is effectively granular to a month.

Failure is otherwise invisible here, so the pipeline is instrumented:
`mxid_audit_write_failed_total` (labelled `no_partition` when the table has run
past its ranges, which is structural rather than transient),
`mxid_partitions_ahead`, `mxid_partition_default_rows`,
`mxid_partitions_dropped_total`.

### Retention floor

Retention is editable at runtime in the console, which means anyone with
`settings.manage` could shorten it — a way to destroy evidence that leaves no
evidence. `audit.min_retention_days` (default 180) is a floor the console cannot
write below, and `Service.AuditPolicy` clamps a stored value up to it when the
purge reads the policy. Clamping on read rather than trusting the stored number
matters because a sub-floor value can only come from a deployment that predates
the floor, a floor raised after the fact, or a hand-edited row — and in all three
the floor is the safer reading. It can only ever retain MORE than was asked for.

### Off-host mirror and alerting

The chain proves nobody rewrote history. It says nothing about someone with
database access dropping the table, and that is what an off-host copy survives.

`pkg/auditsink` mirrors every persisted record to a syslog collector (RFC 5424
over UDP / TCP / TCP+TLS), hooked into `createLog` after the write succeeds. The
load-bearing property is that **it never blocks**: forwarding runs on a path
synchronous with every write API in the product, so a collector that stops
reading must not be able to stall the service. The queue is bounded and overflow
is dropped and counted (`mxid_audit_forward_total{result="dropped"}`), never
waited on — the record is still in the database, so what a stalled collector
costs is the mirror's completeness, not availability.

`internal/domain/auditalert` is the other half: events named in
`alert_on_event_types` are POSTed to the configured webhook. Delivery rides the
transactional **outbox**, not a goroutine, because an alert about a security
event is exactly what must not be lost to a restart; and it goes through
`pkg/safehttp`, because an administrator-supplied URL is otherwise an SSRF
primitive. A Redis cooldown collapses repeats of one event type for five minutes
and reports the suppressed count on the next alert — ten thousand failed logins
is one incident, and a channel that floods gets muted, which is the same as not
having one.

Configuration is split deliberately: the collector address is boot-time config
(where the audit stream points is itself a security control, and an
administrator who can silently redirect it into a black hole has undone the
reason for having it), while the alert webhook is a runtime setting.

## Credential bootstrap and forced password change

Migration 000009 seeds an `admin` account with a password written in plaintext
in that migration's first line, in this public repository. Nothing changed it,
warned about it, or forced it to be changed, so every production install started
with a super-admin credential any reader of the source already had.

`bootstrap.SecureSeededAdmin` runs before the router accepts a request. In
release mode, an account still carrying that exact bcrypt hash either takes the
password from `MXID_BOOTSTRAP_ADMIN_PASSWORD` or is **locked**. Locking rather
than merely gating is the point: a gated session can still reach the
change-password endpoint, so anyone who knew the published password could have
signed in and set a new one — an account takeover, not a blocked login. The hash
equality test is what keeps this safe to run repeatedly and against an existing
install: bcrypt salts, so it matches the seeded row and nothing else, including
another account that happens to use the same weak password. Debug builds are
untouched, because the seeded password is what the README, the demo seed and the
smoke tests are built around.

Deliberately **not** generated-and-logged: the logger redacts any field whose key
looks like a credential (`internal/bootstrap/logger.go`), so a generated password
would reach the operator as `***`, and defeating that filter to ship a secret
into the log pipeline is the wrong trade.

`must_change_pwd` is the second half. It was written by every administrative
password reset and documented as forcing a change at next sign-in; the only thing
that read it was a badge on the console user-detail page, so the reset's promise
was never kept. The flag is now decided in `session.Manager.Create` — the single
session-creation chokepoint, mirroring `EnrollDecider` — so password, SMS,
magic-link and external-IdP logins are all covered rather than each handler
having to remember. `authn.PwdGateMiddleware` then blocks the session from
everything except `/security/password`, and self-heals once the database says
nothing is owed.

## JIT privileged access

`internal/domain/access` implements request-based temporary elevation (rule-based, no vaulted
accounts). Flow: admin defines an **eligibility** (which role/group, max duration, approver
scope) → user files a **request** with justification → an approver **approves** under
separation-of-duties (self-approval is a hard error), per-eligibility approver scoping, and an
optional step-up MFA requirement (default on) → approval creates a **time-bound binding** →
an **expiry sweeper** (leader-elected, `KeyAccessSweeper`) revokes lapsed bindings → a
**CompositeTerminator** then forces downstream logout per app protocol: OIDC back-channel
logout, SAML IdP-initiated SLO, or CAS SLO (best-effort). All routes are gated behind the
EE `conditional_access` feature via `middleware.RequireFeature`.

## Offboarding & durable delivery

Revoking a departing user's access is tiered by how much MXID controls the
target (`internal/domain/offboarding`):

- **L1 — SSO cut (CE).** One admin action disables the account (which also makes
  the OIDC refresh grant reject the user) and kills every session across the
  console / portal / protocol namespaces, then back-channel-logs-out the apps the
  user is signed into. This revokes access to every app reached through MXID SSO,
  with no downstream credentials.
- **L3 — review checklist (CE).** Records the user's app footprint as a console
  review panel so an admin can confirm cleanup for apps that also hold local
  accounts, and (optionally) fires a signed webhook to the customer's IT/HR/ITSM
  system.
- **L2 — downstream deprovision (EE).** For an app with provisioning enabled, an
  EE-only SCIM 2.0 connector (`mxid-ee/features/scim`, license-gated `scim`)
  deactivates the downstream account (`PATCH active=false`). The per-app config
  schema (`internal/domain/provisioning`) is CE; only the connector is EE.

Side effects that must survive a crash (the offboarding webhook, the SCIM
deprovision) ride a **transactional outbox** (`internal/outbox`, `mxid_outbox`):
producers `EnqueueTx` in the same DB transaction as the state change, and a
worker claims due rows with `FOR UPDATE SKIP LOCKED` (replica-safe, no leader
election needed), dispatches by kind, and backs off / dead-letters on failure.
The in-memory event bus is at-most-once, so security actions never ride it.

## High availability

The binary is replica-safe; nothing assumes a single instance:

- **Single-writer jobs** run under Postgres advisory-lock leader election
  (`pkg/dlock.RunAsLeader`): audit chainer, audit anchorer, audit retention, dynamic-group
  reconcile, API-token purge, JIT expiry sweeper. Non-leaders idle until failover.
- **Cross-pod cache invalidation**: settings changes publish on a Redis pub/sub channel so
  every replica drops its cached copy immediately.
- **Migrations** run via golang-migrate at startup; its Postgres driver holds an advisory
  lock, so concurrently booting replicas don't race.
- **Outbox** claims with `FOR UPDATE SKIP LOCKED`, so any replica may host the worker.
- **`/readyz`** for readiness probes; SIGTERM triggers graceful HTTP shutdown and stops the
  background workers via a shared context.
- **Every goroutine is started through `pkg/safego`** (or `App.SpawnWorker`, which wraps it and
  registers with the shutdown WaitGroup). An unrecovered panic in ANY goroutine terminates the
  process, so a defect whose blast radius should be one background job takes every login down
  instead — and when the trigger is persisted data it survives the restart, which is
  CrashLoopBackOff rather than an incident. A panic now costs the one job and is logged with its
  stack; recovering is not a substitute for fixing it, it decides whether the fix happens during
  an outage. A guard test rejects a new bare `go func`, because nine of these were written by
  people who knew the rule.

## Error contract

`pkg/errcode` is the single registry mapping domain sentinel errors to `(HTTP status, stable
numeric business code)` pairs. Handlers end error paths with `response.MapError(c, err)`, which
unwraps to the registered sentinel; unregistered errors become a 500 via
`response.InternalError`, which logs the real cause server-side and never leaks it to the
client. The frontend localizes known numeric codes in `extractMessage` — one toast per error.

Every numeric code is declared once in `pkg/errcode/catalog.go`, classified as **Generic** or
**Localized**. The distinction is load-bearing: for a Localized code the SPA *discards* the
server message and renders a fixed translated sentence keyed on the number
(`toast.tsx` `LOCALIZED_CODES`), so reusing one for an unrelated error shows the user the wrong
sentence. Generic codes are meant to be shared — the number says "rejected", the message says
why. Call sites pass named constants, never literals.

Guards in `pkg/errcode` enforce this: no bare numeric literal at a `response.*` call, every
referenced constant catalogued, no Localized code carrying two different messages, and the
Localized set identical on both sides of the wire. That last one is why the frontend's
`LOCALIZED_CODES` cannot drift from the Go catalog without failing a test.

## Invariants enforced by tests

Several rules here cannot be expressed in the type system and had already been broken once each,
so they are asserted by tests rather than documented and hoped for:

| Rule | Enforced by |
|---|---|
| No unscoped raw SQL against a tenant-scoped table | `pkg/tenantscope/raw_guard_test.go` |
| No unscoped `.Table()` lookup (the plugin keys off the model type, so an anonymous scan struct escapes it) | `pkg/tenantscope/table_guard_test.go` |
| Every business code catalogued; Localized codes unique and in step with the SPA | `pkg/errcode/catalog_guard_test.go` |
| Every dependency-wiring struct in `app` covered by `exhaustruct` | `app/wiring_test.go` |
| A `<Field required>` label carries no asterisk of its own (the primitive draws it) | `scripts/verify-i18n-markers.mjs` |
| Package `app`'s exhaustruct list has no stale entries | `app/wiring_test.go` |
| Session revocation covers every namespace and survives a cancelled publisher context | `app/session_revocation_test.go` |
| A brute-force lockout does NOT revoke sessions (revoking would be a denial of service) | `app/session_revocation_test.go` |
| Audit retention cannot be shortened past the deployment's floor | `internal/domain/setting/audit_retention_floor_test.go` |
| Audit forwarding never blocks the audit write | `pkg/auditsink/sink_test.go` |
| An alert storm is collapsed rather than delivered once per event | `internal/domain/auditalert/dispatcher_test.go` |
| A release deployment never serves with the seeded administrator password | `internal/bootstrap/admin_credential_test.go` |
| A session owing a password change reaches nothing but the change-password route | `internal/domain/authn/password_gate_test.go` |
| No goroutine is started without a recover (an unrecovered panic terminates the process) | `pkg/safego/no_bare_goroutines_test.go` |
| Every error response carries a traceId (no hand-written body) | `pkg/response/no_bypass_test.go` |
| Every event with an audit allow-list is actually subscribed to | `internal/domain/audit/subscription_coverage_test.go` |
| No allow-listed audit field is silently removed by the sensitive-key filter | `internal/domain/audit/schema_honesty_test.go` |
| A snowflake id survives the trip to the client with every digit intact | `internal/domain/audit/id_precision_test.go` |
| The dynamic-group sweeper writes no audit entries (an operator-triggered sync does) | `internal/domain/group/sweeper_audit_test.go` |
| A LIKE value typed by a user is matched literally, not as a wildcard | `pkg/dberr/like_test.go`, `internal/domain/group/rule_like_escape_test.go` |
| A dynamic-group rule value cannot be empty (a blank one matches nearly everyone) | `internal/domain/group/rule_empty_value_test.go` |
| A group code is usable by the systems that receive it in a claim | `internal/domain/group/code_test.go` |
| `errcode.Lookup` returns the most specific bound sentinel, not a random match | `pkg/errcode/lookup_specificity_test.go` |

Each guard was verified by reintroducing the defect it exists to catch. Two of them were wrong on
the first attempt and passed against the broken code — a line-window scan that found a neighbour's
tenant predicate, and a message-bucketing check that collapsed two distinct `err.Error()` sites
into one. Both are now statement-scoped and site-keyed respectively.

## Subject strategy — one setting per protocol

Each app decides what identifier MXID writes into the protocol response
(`mxid_app.subject_strategy`: `username`, `username_suffixed`, `email`, `persistent_id`, or
`pairwise` for OIDC only). The default for a *new* app comes from the tenant's protocol defaults,
and that default is per protocol because the value lands somewhere with a different audience:

| Protocol | Lands in | Default | Why |
|---|---|---|---|
| OIDC | `sub` | `persistent_id` | A machine identifier. Must be opaque and must survive a rename, or every RP loses track of a renamed user. |
| SAML | NameID | `username` | The account name the SP creates. |
| CAS | `cas:user` | `username` | Same — JumpServer, Redmine and Zabbix key local accounts off it, so an opaque id produces accounts named after a snowflake. |

A shared app (`tenant_id IS NULL`) may not use bare `username`: two tenants' `kerbos` would
collide downstream, so `Create` upgrades it to `username_suffixed`.

## Form-fill SSO (SWA) seam

CE ships the `form` application protocol type and its descriptor schema (login URL + field
selectors, stored in the app's `protocol_config`); the portal launch path reads it like any
other protocol. Everything credential-bearing is EE: the encrypted credential vault, extension
token binding, and step-up-gated reveal endpoints live in `mxid-ee/features/formfill`
(license feature `form_fill`, registered through the `RegisterInit` DI seam). The companion
MV3 browser extension is a separate open-source repo
([mxid-extension](https://github.com/imkerbos/mxid-extension)) whose Record mode pushes the
descriptor back to the server — see the README for the user-facing flow.

## Extending — add a new external IdP (EE)

External IdP is a code-separated EE feature; there is nothing to extend in this repo.

1. In `mxid-ee`, implement the provider interface in
   `features/externalidp/providers/` (see `github.go`, `lark.go`, `teams.go`).
2. Register the provider type in `features/externalidp/registry.go`.
3. Add UI: the IdP CRUD page (`web/apps/console/src/pages/idps`) picks up the new `type` from the API automatically; add an icon + label only if you want them branded.

## Extending — add a new protocol

1. New package under `internal/protocol/<name>/`.
2. Implement handler, route registration, and ticket / token store as needed.
3. Add `<name>.Register(...)` call in `app/run.go`, alongside CAS / SAML / OIDC.
4. Add a row to `app.Protocol` constants + `ProtocolDefaults` setting + UI dropdown.

## Editions & licensing (CE / EE)

Open-core, single source of truth, no fork. The server entrypoint lives in the
importable package `github.com/imkerbos/mxid/app` (`app.Run()`); `cmd/server` is
a thin `main` that calls it. The EE distribution (`github.com/imkerbos/mxid-ee`,
private) is its own module that imports `app`, blank-imports its feature
packages, and runs the same `app.Run()`.

- **`pkg/ee/license`** — verifies an Ed25519-signed token against an embedded
  public key (the private key lives only in the `license-authority` repo). Holds
  the process-wide `Current()` Manager; CE by default, EE when a valid license is
  loaded from the License setting (DB-persisted, console-activated, hot-reloaded).
  Offline + product-bound; expiry reverts to CE limits with existing data
  grandfathered.
- **`pkg/ee/registry`** — the extension seam. EE feature packages call
  `registry.RegisterConsole(...)` / `registry.RegisterInit(...)` from `init()`;
  `app.Run` invokes the registered mounters. CE imports none, so EE code is
  *absent* from the CE binary.
- **Two gating tiers**:
  - *Runtime-gated* (`middleware.RequireFeature` → `license.Current().Has(feature)`):
    `branding`, `conditional_access`. The code and DB schema ship in the CE binary
    (the schema is foundational / grandfathered); the capability is locked behind
    a license check at the HTTP layer and unlocked when a valid EE license is
    present.
  - *Code-separated*: `external_idp`, `scim`, `form_fill` exist **only** in the
    private `mxid-ee` module and in `garble`-obfuscated EE images, registered at
    startup via `pkg/ee/registry` (`RegisterConsole` for route mounting,
    `RegisterInit` / `InitContext` for the DI seam). The CE binary contains none
    of their code; their routes return 404 on CE. Further keys (`webauthn`,
    `sms`, `advanced_stepup`, `multi_tenant`) are reserved in the catalog but
    never grant — SMS OTP and step-up MFA actually ship in CE, ungated.
    `ImplementedFeatures` in `pkg/ee/license` is the single source of truth.
- **Feature advertisement** (`/api/v1/system/info`): the endpoint reports only
  the features actually registered in the running binary. CE binaries do not list
  `external_idp` (its package is absent; the route does not exist). EE binaries
  list it only after the package has been blank-imported and its `init()` has
  called `registry.Register*`. This prevents clients from relying on a feature
  that the current binary cannot serve.

User-facing matrix, activation, and limits: [EDITIONS.md](EDITIONS.md).

## Things deliberately not done

- **Multi-tenancy** — permanently out of scope, in CE *and* EE. The tenant column
  stays as a schema artefact only (see "Tenant column" above).
- **Federation across MXID instances** — no IdP-to-IdP brokering between MXID deployments.
- **WebAuthn / FIDO2** — only TOTP for MFA today (`webauthn` is a reserved EE catalog
  key with no shipping code).
- **SCIM inbound provisioning** — MXID is not a SCIM *service provider* (no inbound
  create/update of MXID users via SCIM). Outbound SCIM 2.0 *deprovisioning* exists
  for offboarding (L2, EE) — see above.
- **DPoP / OAuth 2.1 strict token binding** — the token endpoint stays on Bearer.
- **JIT user provisioning from external IdP** — exists per-IdP (EE) but not configurable through UI.
