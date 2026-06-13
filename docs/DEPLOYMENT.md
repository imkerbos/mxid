# Deployment

This guide covers running MXID in production. The dev quick-start lives in the [README](../README.md#quick-start).

## Topology

MXID uses a **single-domain, path-prefixed** routing model — the same convention as Keycloak / GitLab / Nextcloud:

```
https://<host>/                       → portal SPA          (end-user login + my-apps)
https://<host>/admin/                 → console SPA         (admin)
https://<host>/api/v1/console/...     → backend REST        (admin auth)
https://<host>/api/v1/portal/...      → backend REST        (end-user auth)
https://<host>/api/v1/portal-public/  → backend REST        (pre-auth: pwd reset / magic link / SMS)
https://<host>/api/v1/openapi/...     → backend REST        (API token auth)
https://<host>/api/v1/system/...      → backend REST        (public bootstrap / info)
https://<host>/protocol/oidc/...      → OIDC IdP
https://<host>/protocol/saml/...      → SAML IdP
https://<host>/protocol/cas/...       → CAS IdP
https://<host>/static/...             → backend static
https://<host>/health                 → liveness probe
```

dev (`http://localhost:3500/...`) and prod (`https://id.example.com/...`) only differ by host. Integration docs, OIDC `redirect_uri` allowlists, and CAS service URLs all use this scheme verbatim.

### Two-pod runtime

```
                    ┌─────────────────────────────────┐
                    │  mxid-nginx pod                 │
   external traffic │  ├─ TLS terminate              │
   ───────────────► │  ├─ /admin/* → console dist    │  (volume / configmap mount)
                    │  ├─ /*       → portal  dist    │  (volume / configmap mount)
                    │  └─ /api/*, /protocol/*,       │
                    │     /static/*, /health         │
                    │            ▼ reverse proxy     │
                    └────────────│────────────────────┘
                                 ▼
                    ┌─────────────────────────────────┐
                    │  mxid-backend pod (Go binary)   │
                    │  no static files — pure REST    │
                    └─────────────────────────────────┘
                                 │
                  ┌──────────────┼──────────────┐
                  ▼              ▼              ▼
              PostgreSQL       Redis        SMTP/SMS
```

The nginx pod holds the SPA dist directories (mounted as volumes or baked into a custom image); the backend pod is a stateless Go binary. The two are deployable, scalable, and updatable **independently** — push a new frontend by replacing the dist mount; push a new backend by rolling the Go binary.

External URLs are admin-editable at **Console → Settings → External URLs**, so you can swap the canonical hostname at runtime without restarting. The handlers also auto-swap `localhost` for the inbound request host in dev / LAN-IP scenarios.

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| Go | 1.23+ | Build the binary. Not needed at runtime. |
| Node | 22+ | Build the SPAs. Not needed at runtime. |
| PostgreSQL | 15+ | Primary data store. Extensions: `pg_trgm` (auto-installed by migration 0030). |
| Redis | 7+ | Sessions, tickets, TOTP rate-limit, event SSE. AOF or RDB persistence recommended. |
| SMTP | any | Optional. Without SMTP, password-reset / magic-link emails fall back to a `dev_link` in the API response. |

## Configuration

Configuration is resolved in this order (highest precedence first):

1. Environment variables prefixed `MXID_` (e.g. `MXID_SERVER_PORT`).
2. `configs/config.prod.yaml` (when `MXID_CONFIG_ENV=prod`).
3. `configs/config.yaml` (defaults).

The `.env.example` file lists every supported variable.

### Required secrets

| Variable | Purpose | How to generate |
|----------|---------|-----------------|
| `MXID_MASTER_KEY` | AES-encrypts sensitive settings (SMTP password, SMS secret, OAuth client secrets at rest). | `openssl rand -base64 32` |
| `MXID_JWT_PRIVATE_KEY` | Signs OIDC id_token / access_token. | RSA 2048: `openssl genrsa 2048` |
| `MXID_SESSION_SECRET` | HMACs session cookies. | `openssl rand -base64 32` |

Rotating `MXID_MASTER_KEY` requires re-encrypting existing settings — see [`scripts/rotate-master-key.sh`](../scripts) (TODO).

## Container images & versioning

Two images, published to GitHub Container Registry — prod is fully containerized
(no host-side build, no `dist/` mounts):

```
ghcr.io/imkerbos/mxid       # Go backend
ghcr.io/imkerbos/mxid-web   # nginx + both SPAs baked in
```

Releases are tag-driven. Pushing a SemVer git tag (`vMAJOR.MINOR.PATCH`) runs
`.github/workflows/release.yml`, which builds both images multi-arch
(`linux/amd64` + `linux/arm64`), pushes the standardized tag set below, and cuts
a GitHub Release. Nothing is built on `main` or PRs — CI exists only to release.

| Tag | Moves? | Use |
|-----|--------|-----|
| `v1.2.3` | never (immutable) | **pin this in prod** |
| `v1.2` | latest patch of 1.2 | track patch fixes |
| `v1` | latest minor of 1 | track a major line |

There is **no `latest` tag** — prod must pin an explicit version. The backend
runs DB migrations on boot, so a moving tag would mean a surprise migration.

The same identifier runs end to end: **git tag = image tag = binary version
(`/health`, `/system/info`, console version page) = `MXID_TAG` in `.env`.** Cut
a release:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Production with Docker compose

Deployment touches **one file — `.env`**. You never edit the YAML config or the
compose files; env overrides win, and everything else (domain, SMTP, branding…)
is set in the console after first login.

```bash
git clone https://github.com/imkerbos/mxid.git   # only for compose files + .env + certs
cd mxid
cp .env.example .env
```

Edit `.env` — the prod section:

```ini
# Mode: external DB (default) — or uncomment the second line for a
# self-contained stack with containerized Postgres + Redis + volumes.
COMPOSE_FILE=deploy/compose/docker-compose.yml
# COMPOSE_FILE=deploy/compose/docker-compose.yml:deploy/compose/docker-compose.standalone.yml

MXID_TAG=v0.1.0                                      # required — pin a release
MXID_SERVER_ALLOWED_ORIGINS=https://id.example.com   # CORS/CSRF allow-list (boot-time)
SERVER_NAME=id.example.com
CERT_FILE=fullchain.pem
KEY_FILE=privkey.pem
# secrets: POSTGRES_PASSWORD / REDIS_PASSWORD / MXID_CRYPTO_KEY_ENCRYPTION_KEY
```

Drop your TLS cert + key into `deploy/compose/cert/` (named per `CERT_FILE` /
`KEY_FILE`), then:

```bash
docker compose up -d          # COMPOSE_FILE from .env selects the mode
```

That's it — `docker compose` reads `COMPOSE_FILE` from `.env`, pulls the matched
backend + web images, and starts. (Building locally instead of pulling:
`make prod-up` / `make standalone-up`.)

**Why only those env values?** `MXID_SERVER_ALLOWED_ORIGINS` is the CORS/CSRF
allow-list — it must be known at startup because it gates who can even reach the
console to change other settings. Everything else URL-related (issuer / portal /
console URLs that protocol handlers use) is **set in the console** under
*Settings → 外部 URL* and takes effect live; the YAML values are only a fallback.

- TLS certs are operator-supplied, mounted from `deploy/compose/cert/`, never baked into the image.
- Behind an existing ingress (Traefik, Caddy, ALB)? Terminate TLS there and forward plain HTTP to the web container — drop the cert mount and the `listen 443 ssl` block from `prod.conf`.

### Reverse proxy headers

MXID trusts `X-Forwarded-For` + `X-Forwarded-Proto` only when configured to do so:

```yaml
server:
  trusted_proxies:
    - 127.0.0.1
    - 10.0.0.0/8
```

If the proxy doesn't add these headers, leave `trusted_proxies` empty so MXID treats the proxy IP as the client IP.

## Production checklist

- [ ] HTTPS everywhere. Set `server.cookie_secure: true`.
- [ ] `server.cookie_domain` set if the portal + console are on subdomains of the same parent.
- [ ] `MXID_MASTER_KEY`, `MXID_JWT_PRIVATE_KEY`, `MXID_SESSION_SECRET` are strong + private.
- [ ] PostgreSQL `max_connections` ≥ Go `database.max_open_conns` × replica count.
- [ ] Redis persistence (AOF `everysec` or RDB at suitable interval).
- [ ] DB backup configured (`pg_dump` / WAL archiving).
- [ ] **Console → Settings → External URLs** set to the canonical https URLs.
- [ ] **Console → Settings → SMTP** configured AND test mail succeeds.
- [ ] **Console → Settings → Security Policy** reviewed (min length, history, lockout, captcha thresholds).
- [ ] **Console → Settings → Audit Policy** has a sane `retention_days` + (optional) `alert_webhook_url`.
- [ ] First-login admin password rotated. MFA enrolled.
- [ ] App access policies set (no app is `allow public` unless intentional).
- [ ] `trusted_proxies` set if behind a reverse proxy.

## Migrations

Migrations run automatically on backend startup. To run manually:

```bash
make migrate-up                 # apply all
make migrate-down               # rollback most recent
make migrate-create NAME=foo    # scaffold a new migration pair
```

DB schema is **forward-only in production**. The down migrations exist for local dev / CI cleanliness.

## Observability

- Backend writes structured JSON logs to stdout (`level`, `ts`, `caller`, `msg`).
- Request ID propagation via `X-Request-Id` header.
- `/health` endpoint for liveness probes.
- Audit log is the primary security-relevant signal — query the `mxid_audit_log` table or wire up the alert webhook.

## Upgrade

1. Read [CHANGELOG.md](../CHANGELOG.md) for the target version's notes.
2. Back up the database (`pg_dump`).
3. Pull the new tag, rebuild, restart. Migrations run on startup.
4. Verify the integration playbooks under console `/docs` still pass for your critical SPs.

## Troubleshooting

| Symptom | Probable cause | Fix |
|---------|----------------|-----|
| OIDC token has `iss` = `http://localhost:10050` | `ExternalURLs.IssuerURL` empty + `config.IssuerURL` is localhost | Set `ExternalURLs.IssuerURL` in console settings. |
| CAS app returns `application not found` | App `code` mismatch | `/protocol/cas/<code>/login` path segment is the DB `code` column. |
| Toast "已保存" not visible after settings save | Monorepo Tailwind `@source` lost | Verify `web/apps/<app>/src/index.css` has `@source "../../../packages/shared/src/**/*.{ts,tsx}"`. |
| Login redirect loop in portal | Cookie domain mismatch | Set `server.cookie_domain` to the shared parent domain. |
