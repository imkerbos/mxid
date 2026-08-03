# CLAUDE.md — MXID

Operating rules for AI agents working in this repo. These override default
behaviour. Read the whole file before the first edit.

## Hard rules (violating any of these is a defect)

| # | Rule |
|---|---|
| 1 | Reply to the user in **Chinese**. Code, commits, PRs, comments in **English**. |
| 2 | **No AI/Claude/Anthropic attribution** in commits or PRs — no `Co-Authored-By`, no "generated with". |
| 3 | **Never auto-commit.** Implement first; commit only when asked. |
| 4 | All outbound server HTTP goes through **`pkg/safehttp`**. Never a bare `http.Client`. |
| 5 | Every console write route needs **`authz.Require` + `authz.Protect` + a `consoleProtectedRoutes` entry**, or it 403s. |
| 6 | Every write API **records an audit entry** (who / ip / when / what / result). |
| 7 | **Never commit secrets.** Env / `.env` only. |
| 8 | Every frontend write gives **toast feedback** — never silent. |
| 9 | User-visible change → **`CHANGELOG.md` bullet in the same commit**. |

## Project

MXID is a commercial-grade, open-core IAM/SSO platform (OIDC / SAML / CAS).
Benchmarked against Keycloak / Auth0 / Okta / TopIAM. Always take the
spec-compliant production path — no shortcuts, no demo-grade stubs. Prefer
mature, high-star OSS for security/standard components; self-build only the glue.

Copyright © MatrixPlus. Pushed to both `imkerbos` (personal) and the `MatrixPlus`
org; canonical namespace stays `imkerbos/mxid` (images `ghcr.io/imkerbos/...`).

## Working agreement

- **Evaluate then act.** For "评估 / 看看 / 分析" give conclusions only, don't
  touch code. For build tasks, propose a plan first unless told
  "直接干 / 开干 / 全做".
- Surface tradeoffs and real bugs you find; don't silently work around them.
- Be honest about what's verified vs not. Say so when CI is the only verifier.

### Git

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`;
  scopes like `feat(ee):`).
- Default branch is `main`. Never force-push a shared branch without asking.
- **Squash-merge feature branches** — one Conventional-Commit summary per
  feature on the target branch, not `--no-ff` preserving every intermediate
  commit. Keep granular commits while working; squash at merge. Promote
  `dev` → `main` as usual.
- CE and EE release in **lockstep**: the same `vX.Y.Z` tag on both repos. EE
  release CI checks out the CE tag of the same name and fails on a mismatch.
  Push the CE tag first.

## Stack

- **Backend** — Go (Gin + GORM + Redis + Snowflake IDs + bcrypt). `go 1.25.12`;
  pin `golang:1.25.12-alpine` in Docker / dev compose (the floating
  `1.25-alpine` tag lags a patch behind and breaks builds).
- **Frontend** — React 19 + Vite + TypeScript + Tailwind v4, pnpm workspaces
  (`web/apps/console`, `web/apps/portal`, `web/packages/shared`).
- **Data** — PostgreSQL 15 (primary), Redis 7 (sessions / tickets / TOTP
  rate-limit / SSE).

## Architecture invariants

- Entry point is `app.Run()` in package `github.com/imkerbos/mxid/app`
  (importable; the EE distribution reuses it). `cmd/server/main.go` is a thin
  shim. `app/run.go` is a ~1300-line adapter god file — edit carefully, never
  `sed`-split it, and commit before large moves.
- **Gateways**: `internal/gateway/console` (admin REST) +
  `internal/gateway/portal` (end-user REST).
- **Protocols**: `internal/protocol/{oidcop,oidclogout,saml,cas,resolver}`. The
  OIDC engine is `zitadel/oidc` v3 — the sole provider since v1.2.0, no
  hand-rolled engine. Consequences: `response_type=code` only,
  `offline_access` required for a refresh token, `client_secret_jwt`
  unsupported (use `private_key_jwt`).
- **Settings domain**: SMTP / security / branding / login-methods / protocol
  defaults / external URLs are admin-editable at runtime (hot-reload), not env.
- **Single-tenant, permanently.** The `tenant_id` column is a foundational
  schema artefact, not a product capability. `pkg/tenantscope` still enforces
  row scoping defensively — do not remove it.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full picture.

## Security baselines (non-negotiable)

- **Outbound HTTP** — everything server-side goes through `pkg/safehttp` (SSRF
  guard; re-checks the resolved IP on every dial and redirect).
- **authz** — the console gateway is **hard deny-by-default**: a new console
  route that isn't declared in `consoleProtectedRoutes` (in `app/authz_console.go`)
  **403s at runtime**, and a startup check flags it. Gate writes with
  `authz.Require(perm, scope)` + `authz.Protect`. Gin middleware only applies to
  routes registered *after* `.Use` — verify with `curl` after rewiring routes.
- **Audit** — every write API records who / ip / when / what / result. Entries
  land in the tamper-proof chain (see [docs/AUDIT-CHAIN-DESIGN.md](docs/AUDIT-CHAIN-DESIGN.md));
  a capture failure aborts the business write by design.
- **Secrets** — never commit them. Use env / `.env` (+ godotenv).
  `MXID_CRYPTO_KEY_ENCRYPTION_KEY` is the master KEK. `validateSecrets` rejects
  dev placeholders in release mode. Maintain the leaked-dev-KEK blacklist.
- **Step-up MFA** on high-risk ops (deletes, security-critical writes); the sudo
  window stays consistent across portal and console.
- **GORM scan structs need explicit `gorm:"column:..."` tags.** EE release
  builds run `garble -tiny`, which renames fields; an untagged field silently
  scans empty. Enforced by `make verify-gormtags`.

## Editions (CE / EE)

- Open core. CE = AGPL-3.0 ([LICENSE](LICENSE)); EE = commercial
  ([LICENSE.EE](LICENSE.EE)). Split documented in [docs/EDITIONS.md](docs/EDITIONS.md).
- **Licensing** — Ed25519-signed offline token verified against the embedded
  public key in `pkg/ee/license`. The private key lives only in the
  `license-authority` repo. DB-only activation (console → Settings → License),
  hot-reloaded; **never echo the token back to the UI**.
- `license.Current()` is the single source of truth for gating. CE cap:
  `CEMaxUsers = 100`. EE is unlimited unless the license sets `MaxUsers`.
- **Expiry = graceful downgrade to CE limits.** Logins/SSO keep working,
  existing data is grandfathered; only new creation past the CE cap is blocked.

### Two gating tiers

- **Runtime gate** (`middleware.RequireFeature` → 403) — the code ships in CE
  because the schema is foundational; only the capability is licensed. Used by
  `branding`, `conditional_access`.
- **Code separation** — the feature exists ONLY in the private `mxid-ee` repo,
  is absent from the CE binary, and is `garble`-obfuscated. It self-registers
  through `pkg/ee/registry` (`RegisterConsole` for a console route, or the
  `RegisterInit`/`InitContext` DI seam for a fuller feature). Used by
  `external_idp`, `scim`, `form_fill`. The reusable gate is `pkg/ee/feature`,
  which `internal/middleware.RequireFeature` delegates to so EE packages — in a
  separate Go module — can gate their own routes.

### Feature keys

- **Implemented and sold**: `external_idp`, `branding`, `conditional_access`
  (gates JIT privileged access), `scim` (outbound deprovision), `form_fill`.
- **Reserved keys that NEVER grant**: `webauthn`, `sms`, `advanced_stepup`,
  `multi_tenant`. Note SMS OTP and step-up MFA actually ship in CE ungated —
  never quote them as EE differentiators.
- `ImplementedFeatures` in `pkg/ee/license` is the single truth. Shipping a
  feature means adding it there — that is what lights it up for existing
  customers, with no re-issued license. Update `docs/EDITIONS.md` in the same PR.

## Frontend conventions

- UI primitives (Button / Input / Field / Modal / toast) come from
  `@mxid/shared`, shared between console and portal.
- **Every write (save / create / delete / upload) gives toast feedback**
  (`toast.success` / `toast.error`) — never silent.
- One notification per error: an API error produces a single toast, not a toast
  plus inline text. The backend returns a stable numeric code; the frontend
  localizes known codes in `extractMessage`. A raw axios error's `.code` is a
  string — read the numeric code from `response.data.code`.
- Tailwind v4: each app's `index.css` needs
  `@source "../../../packages/shared/src/**/*.{ts,tsx}"` or shared-component
  classes get purged.
- i18n keys built dynamically (`t(\`apps.protocolFields.${p}.${k}.label\`)`) are
  invisible to a literal search — keep the whole prefix subtree when pruning.

## Docs stay in sync with code (non-negotiable)

- User-visible change in `internal/` or `web/` → a bullet under
  `[Unreleased]` in `CHANGELOG.md`, **in the same commit**.
- Architecture-shaped change (new domain package, new `pkg/`, protocol or
  auth-flow change, new seam) → `docs/ARCHITECTURE.md` in the same PR.
- New env var / helm value / compose knob → `docs/DEPLOYMENT.md` +
  `docs/DEPLOYMENT_ZH.md` + `.env.example`.
- Feature-gate change → `docs/EDITIONS.md` + the README feature tables
  (EN and ZH, kept mirrored).
- Cutting a release: rename `[Unreleased]` → `[X.Y.Z] — date`, add the compare
  link at the bottom, bump helm `Chart.yaml` `appVersion` and `values.yaml` tag.
- A design doc whose feature has shipped moves to `docs/archive/`, or is deleted
  if it has no reference value. **Stale plans are worse than no plans.**

## Dev / deploy

- **Dev**: `make dev-up` (`EE=1` for the Enterprise backend) brings up the ONE
  dev stack — postgres, redis, backend (air), console/portal vite, nginx on
  :3500. Postgres/Redis are compose services in project `mxid-dev` with their
  own `mxid-dev_pgdata` / `mxid-dev_redisdata` volumes; host ports 5432/6379
  stay published for psql/DBeaver. **Never start dev infra outside compose** —
  that is how dev data ends up in a volume no compose file owns. `make dev-down`
  keeps data; only `make dev-nuke` deletes it (and it prompts).
- `make seed-demo` (re)seeds the demo org/groups/memberships/app-access so demo
  users actually see apps in the portal. Idempotent.
- **Prod**: released images from GHCR behind nginx on 80/443; one `.env` drives
  it (`COMPOSE_FILE` selects the mode). Tag `v*.*.*` → CI builds and publishes
  (no `latest` tag). See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
- **Pre-commit hook** runs `verify-mod / vet / build / gormtags / exports`. Keep
  it green; don't `--no-verify` without saying so.
- Repo-root tool configs (`.air.toml`, `.golangci.yml`, `.dockerignore`) are
  **shared project config and are committed** — CI and the Makefile read them.
  Never gitignore them.

## Where to look

| Question | File |
|---|---|
| How is the system built? | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| What changed, and when? | [CHANGELOG.md](CHANGELOG.md) |
| What's CE vs EE? | [docs/EDITIONS.md](docs/EDITIONS.md) |
| How do I deploy it? | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| How does the audit chain work? | [docs/AUDIT-CHAIN-DESIGN.md](docs/AUDIT-CHAIN-DESIGN.md) |
| How do I wire app X to SSO? | [docs/integrations/](docs/integrations/) |
| What are the local dev gates? | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Why was it built this way? | [docs/archive/](docs/archive/) (frozen; code wins) |
