# Deployment

**English** · [简体中文](DEPLOYMENT_ZH.md)

This guide covers running MXID in production. The dev quick-start lives in the [README](../README.md#quick-start-development).

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
https://<host>/health                 → liveness probe (process alive)
https://<host>/readyz                 → readiness probe (pings DB + Redis; 503 when not ready)
https://<host>/metrics               → Prometheus metrics (keep INTERNAL-ONLY at the edge)
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
| Go | 1.25+ | Build the binary. Not needed at runtime. |
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

In `release` mode the backend refuses to start unless these are set to real
values (it rejects dev placeholders). Compose aborts if any is missing.

| Variable | Purpose | How to generate |
|----------|---------|-----------------|
| `MXID_CRYPTO_KEY_ENCRYPTION_KEY` | Master KEK — AES-encrypts OIDC signing keys + sensitive settings (SMTP/SMS secrets, OAuth client secrets) at rest. **Unique per deployment; rotating it invalidates existing app signing keys.** | `openssl rand -base64 32` |
| `MXID_CRYPTO_AUDIT_CHAIN_KEY` | HMAC key for the tamper-proof audit hash-chain. **Generate ONCE and never change — rotating it makes every existing audit entry fail verification** (same stability class as the KEK). | `openssl rand -base64 32` |
| `MXID_CRYPTO_AUDIT_ANCHOR_KEY` | Ed25519 seed that signs the external Merkle anchors. Required when `audit.anchorSink.enabled` (the default). May be rotated only if the old public key is kept in `crypto.audit_anchor_retired_pubkeys` so old anchors still verify. | `openssl rand -base64 32` |
| `POSTGRES_PASSWORD` (→ `MXID_DATABASE_PASSWORD`) | PostgreSQL password. | strong random |
| `REDIS_PASSWORD` (→ `MXID_REDIS_PASSWORD`) | Redis password. | strong random |

`release` mode also requires `session.cookie_secure: true` (HTTPS). OIDC token
signing keys are generated + stored (KEK-encrypted) by the app — no key env var.

### Environment reference (`.env`)

Everything for a deploy lives in `.env` (copy from `.env.example`). The full
prod set:

| Variable | Required | Default | Purpose |
|----------|:--:|---------|---------|
| `COMPOSE_FILE` | ✅ | — | Which compose files to load = deployment mode. See *Production with Docker compose*. |
| `MXID_TAG` | ✅ | — | Image version to pin (e.g. `v0.1.0`). No `latest`. |
| `MXID_CRYPTO_KEY_ENCRYPTION_KEY` | ✅ | — | Master KEK (`openssl rand -base64 32`). |
| `MXID_CRYPTO_AUDIT_CHAIN_KEY` | ✅ | — | Audit hash-chain HMAC key (`openssl rand -base64 32`). Generate once, never change. |
| `MXID_CRYPTO_AUDIT_ANCHOR_KEY` | ✅* | — | Audit anchor Ed25519 seed (`openssl rand -base64 32`). Required in release mode when anchoring is enabled (the default). |
| `MXID_CRYPTO_AUDIT_ANCHOR_RETIRED_PUBKEYS` | — | — | Comma-separated base64 ed25519 public keys retired from anchoring; add the old public key here when rotating `MXID_CRYPTO_AUDIT_ANCHOR_KEY` so old anchors still verify. |
| `MXID_AUDIT_ANCHOR_ENABLED` | — | `true` | Enable/disable audit anchoring. Setting `false` is an explicit opt-out; otherwise release mode requires the anchor key. |
| `MXID_AUDIT_ANCHOR_SINK_PATH` | — | `data/audit-anchors.log` | File the signed audit anchors are appended to. |
| `POSTGRES_PASSWORD` | ✅ | — | DB password. |
| `REDIS_PASSWORD` | ✅ | — | Redis password. |
| `MXID_SERVER_ALLOWED_ORIGINS` | ✅ | — | CORS/CSRF allow-list, comma-separated origins (e.g. `https://id.example.com`). Boot-time. |
| `MXID_SERVER_ISSUER_URL` | ✅ | `https://id.example.com` | Canonical OIDC issuer (`iss`) / SAML EntityID base / CAS root. MUST be your real externally-reachable HTTPS URL — release mode rejects localhost; third parties redirect back to it. |
| `MXID_SERVER_PORTAL_URL` | ✅ | `https://id.example.com` | Canonical portal URL. Single-domain deploy: same as the issuer. |
| `MXID_SERVER_CONSOLE_URL` | ✅ | `https://id.example.com/admin` | Canonical console URL. Single-domain deploy: issuer + `/admin`. |
| `MXID_SERVER_TRUSTED_PROXIES` | — | — | Comma-separated CIDRs of trusted reverse proxies / LBs — the app resolves the real client IP from `X-Forwarded-For` only for these. See *Reverse proxy headers*. |
| `SERVER_NAME` | ✅ | `_` | nginx TLS `server_name` (your domain). |
| `CERT_FILE` | ✅ | `server.crt` | TLS cert filename under `deploy/compose/cert/`. |
| `KEY_FILE` | ✅ | `server.key` | TLS key filename under `deploy/compose/cert/`. |
| `POSTGRES_USER` / `POSTGRES_DB` | — | `postgres` / `mxid` | DB user / name. |
| `POSTGRES_PORT` / `REDIS_PORT` | — | `5432` / `6379` | Host-mapped Postgres / Redis ports (compose). |
| `MXID_DATABASE_HOST` | — | `host.docker.internal` (standalone: `postgres`) | External DB host (external-DB mode only). |
| `MXID_DATABASE_NAME` / `MXID_DATABASE_USER` | — | `mxid` / `postgres` | DB name / user as seen by the backend. |
| `MXID_DATABASE_PORT` / `MXID_REDIS_PORT` | — | `5432` / `6379` | DB / Redis ports as seen by the backend. |
| `MXID_REDIS_HOST` | — | `host.docker.internal` (standalone: `redis`) | External Redis host. |

> **The canonical external URLs (`MXID_SERVER_ISSUER_URL` / `MXID_SERVER_PORTAL_URL` /
> `MXID_SERVER_CONSOLE_URL`) MUST be set to your real HTTPS URLs in production.**
> They are the OIDC issuer (`iss`), SAML EntityID base, CAS root, and the origins
> third parties (Lark and other IdPs/SPs) redirect back to; release mode rejects
> localhost. Without them the app boots on the `id.example.com` placeholder. They
> remain admin-editable at runtime (Console → Settings → External URLs), but the
> env values are what a fresh deployment starts from.
> License is **not** an env var — activate it in the console (DB-stored).

## Container images & versioning

Images on GitHub Container Registry — prod is fully containerized (no host-side
build, no `dist/` mounts):

```
ghcr.io/imkerbos/mxid       # CE backend (public)
ghcr.io/imkerbos/mxid-web   # nginx + both SPAs baked in (shared by CE + EE)
ghcr.io/imkerbos/mxid-ee    # EE backend (private, garble-obfuscated) — see Editions
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

MXID_TAG=v1.8.0                                      # required — pin a release
MXID_SERVER_ALLOWED_ORIGINS=https://id.example.com   # CORS/CSRF allow-list (boot-time)
MXID_SERVER_ISSUER_URL=https://id.example.com        # canonical OIDC issuer / SAML EntityID / CAS root
MXID_SERVER_PORTAL_URL=https://id.example.com        # canonical portal URL
MXID_SERVER_CONSOLE_URL=https://id.example.com/admin # canonical console URL
SERVER_NAME=id.example.com
CERT_FILE=fullchain.pem
KEY_FILE=privkey.pem
# secrets: POSTGRES_PASSWORD / REDIS_PASSWORD / MXID_CRYPTO_KEY_ENCRYPTION_KEY
```

Drop your TLS cert + key into `deploy/compose/cert/` (named per `CERT_FILE` /
`KEY_FILE`), then:

```bash
make prod-docker-up           # equivalent to: docker compose up -d
```

That's it — `docker compose` reads `COMPOSE_FILE` from `.env`, pulls the matched
backend + web images, and starts.

> **Standalone mode** (Postgres + Redis bundled in compose, no external dependencies):
> uncomment the second `COMPOSE_FILE` line. Suitable for single-server trials; for
> production prefer managed Postgres / Redis (see Kubernetes section).

Two **deployment modes** are available via `COMPOSE_FILE`:

| Mode | `COMPOSE_FILE` value | When to use |
|------|----------------------|-------------|
| **External DB** (default) | `docker-compose.yml` | Managed Postgres + Redis (RDS, CloudSQL, ElastiCache…) |
| **Standalone** | `docker-compose.yml:docker-compose.standalone.yml` | Self-contained — Postgres + Redis included |

> **Container name isolation**: dev compose uses `mxid-nginx-dev` for the nginx
> container; prod uses `mxid-nginx`. If you run both on the same host (e.g. a
> build machine that also serves production), the names do not collide and both
> stacks start cleanly.

**Why these env values?** `MXID_SERVER_ALLOWED_ORIGINS` is the CORS/CSRF
allow-list — it must be known at startup because it gates who can even reach the
console to change other settings. The canonical URLs
(`MXID_SERVER_ISSUER_URL` / `MXID_SERVER_PORTAL_URL` / `MXID_SERVER_CONSOLE_URL`)
must be your real external HTTPS URLs from the first boot — they seed the OIDC
issuer / SAML EntityID / CAS root that third parties depend on. They remain
admin-editable at runtime under *Settings → External URLs* (hot-reload); the
YAML config values are only a last-resort fallback.

### TLS certificates

Certs are operator-supplied and mounted read-only from `deploy/compose/cert/`
into the web container — never baked into the image. The web image runs nginx on
`80` (redirects to 443) and `443`; `SERVER_NAME` / `CERT_FILE` / `KEY_FILE` from
`.env` are substituted into the nginx config at startup.

```bash
mkdir -p deploy/compose/cert
# place your cert + key here, named to match CERT_FILE / KEY_FILE in .env
deploy/compose/cert/
├── fullchain.pem      # CERT_FILE — full chain (leaf + intermediates)
└── privkey.pem        # KEY_FILE  — private key
```

**Real certificate (Let's Encrypt / CA-issued).** Use the full chain as
`CERT_FILE`. For Let's Encrypt, `fullchain.pem` + `privkey.pem` from certbot map
1:1 — copy them in (or symlink/renew-hook into this dir). The compose also mounts
`./acme` as an optional webroot for HTTP-01 renewals.

**Self-signed (testing only).**

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout deploy/compose/cert/privkey.pem \
  -out   deploy/compose/cert/fullchain.pem \
  -subj  "/CN=id.example.com"
```

**Behind an existing ingress** (Traefik, Caddy, ALB)? Terminate TLS there and
forward plain HTTP to the web container — drop the cert mount and the
`listen 443 ssl` block from `prod.conf`.

> `deploy/compose/cert/` is gitignored — keys never get committed.

### Community vs Enterprise

The compose above runs **Community Edition**. For **Enterprise Edition**, chain
the EE overlay (swaps the backend to the private `mxid-ee` image) and supply a
license. Full details in [EDITIONS.md](EDITIONS.md); the deploy delta:

```ini
# .env — add the EE overlay
COMPOSE_FILE=deploy/compose/docker-compose.yml:deploy/compose/docker-compose.ee.yml
```

```bash
docker login ghcr.io       # mxid-ee is private — token needs read:packages
docker compose pull
docker compose up -d
```

The license is activated in the console (Settings → License); it's stored in the
DB and hot-reloaded, so it survives image swaps and restarts — no env var. No
license → CE; expired → CE limits with existing data grandfathered.

## Kubernetes deployment

> This section assumes familiarity with Kubernetes. The Docker compose path is
> simpler and fully supported — use Kubernetes only when you need rolling updates,
> horizontal scaling, or cluster-native observability.

### Why MXID is well-suited for Kubernetes

The backend is **fully stateless** — icon uploads are stored in the database (no
local filesystem state), and the frontend SPA is baked into the `mxid-web` image
served by nginx. There is **no PVC required** for the application itself, and no
`ReadWriteOnce` multi-attach deadlock risk. External state (PostgreSQL, Redis) is
the only thing that needs persistence.

### Component mapping

| Role | Kubernetes resource | Notes |
|------|---------------------|-------|
| Backend (`mxid` / `mxid-ee`) | `Deployment` (MVP) or `StatefulSet` (multi-replica) | See *nodeID* below |
| Frontend (`mxid-web`) | `Deployment` | Stateless nginx; any replica count |
| PostgreSQL | External managed (RDS, CloudSQL) or operator (e.g. CloudNativePG) | Do **not** run on raw `Deployment` in prod |
| Redis | External managed (ElastiCache, MemoryStore) or operator | |
| TLS ingress | `Ingress` + cert-manager | Or cloud LB with managed certs |
| DB schema migrations | Automatic on backend startup (advisory lock) | Optional: your own pre-upgrade `Job` — see *Migrations* below |

### nodeID — uniqueness constraint

Each backend replica must have a **unique Snowflake `node_id`** (10-bit,
0–1023). Duplicate node IDs cause primary-key collisions under concurrent load.

**Option A — StatefulSet ordinal (recommended, zero code).** Use a `StatefulSet`
(without `volumeClaimTemplates` — the backend needs no PVC) and pass the ordinal
as the node ID:

```yaml
# StatefulSet pod template
env:
  - name: POD_ORDINAL
    valueFrom:
      fieldRef:
        fieldPath: metadata.annotations['apps.kubernetes.io/pod-index']
  - name: MXID_SNOWFLAKE_NODE_ID
    value: "$(POD_ORDINAL)"
```

This gives replica 0 → `node_id=0`, replica 1 → `node_id=1`, etc. Scale up to
1023 replicas safely.

**Option B — Redis startup lease.** At startup each pod claims the lowest free
node ID from a Redis hash-set. Works with a plain `Deployment` but requires a
Redis connection before the first Snowflake ID is generated.

**Single-replica MVP.** Any fixed value (e.g. `MXID_SNOWFLAKE_NODE_ID=0`) is
fine — no collision risk.

### License fingerprint and PostgreSQL `system_identifier`

The EE license fingerprint is `HMAC(install_uuid | PostgreSQL system_identifier)`.
Because all backend replicas connect to the **same database**, they all compute
the same fingerprint — no per-replica re-activation needed.

**Important**: `system_identifier` is preserved across physical replication and
failover (e.g. Patroni / CloudNativePG switchover). However, a **logical
restore** (`pg_dump` → `pg_restore` into a new cluster) generates a new
`system_identifier`, which invalidates the fingerprint. After a logical restore
to a new cluster, re-activate the license in the console (Settings → License).

### Database migrations

Migrations run automatically on backend startup using golang-migrate with the
postgres driver's **advisory lock** — concurrent pods cannot double-apply a
migration, so a plain rolling update is safe with no extra machinery. The Helm
chart ships **no** pre-upgrade migration-job template on purpose.

If your GitOps / change-management workflow wants explicit control anyway, run
your own `Job` (e.g. a Helm `pre-upgrade` hook in your wrapper chart) that starts
the backend image against the database before the rolling update; the advisory
lock makes the subsequent pod boots no-ops. Either way — automatic or Job — the
advisory lock keeps it safe.

### Health checks

Use **`/health` for liveness** (cheap "is the process alive", no dependency
check) and **`/readyz` for readiness** — `/readyz` pings PostgreSQL and Redis
and returns `503` when either is unreachable, so a pod with a broken dependency
connection is pulled from the Service instead of serving errors. The Helm chart
wires the probes exactly this way:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 10050
  initialDelaySeconds: 10
  periodSeconds: 15
readinessProbe:
  httpGet:
    path: /readyz          # dependency-aware: DB + Redis ping, 503 on failure
    port: 10050
  initialDelaySeconds: 5
  periodSeconds: 10
```

### SSRF and cloud metadata

The backend routes all outbound HTTP through `pkg/safehttp`, which blocks
requests to cloud metadata endpoints (including `169.254.169.254`). No
additional NetworkPolicy is required for SSRF protection at the application
layer, but applying a default-deny egress `NetworkPolicy` is still a good
defence-in-depth practice in shared clusters.

### CE → EE upgrade (zero downtime)

Switching from Community to Enterprise Edition is a one-line image swap — the
same principle as changing the `COMPOSE_FILE` overlay in Docker compose, but
with a rolling update:

```bash
helm upgrade mxid ./helm/mxid \
  --set image.repository=ghcr.io/imkerbos/mxid-ee \
  --set image.tag=v1.8.0
```

Kubernetes performs a rolling update: new EE pods start (registering
`external_idp` and other EE features), then old CE pods terminate. The license
already in the database is picked up automatically — no re-activation. To roll
back:

```bash
helm rollback mxid
```

### Phased rollout

**MVP (single replica)**

```yaml
kind: Deployment
spec:
  replicas: 1
  strategy:
    type: Recreate        # avoids any node_id overlap during rollout
```

Use external managed PostgreSQL and Redis. No PVC needed.

**Production (multi-replica, horizontally scaled)**

```yaml
kind: StatefulSet
spec:
  replicas: 3             # node_id: 0, 1, 2 via pod ordinal
  # no volumeClaimTemplates — backend is stateless
```

Add an `HorizontalPodAutoscaler` on CPU/RPS metrics. Ensure
`PostgreSQL max_connections ≥ database.max_open_conns × replica_count`.

### Deploying with the Helm chart

The repository ships a Helm chart at `deploy/helm/mxid`. It renders the backend
`StatefulSet`, the web `Deployment`, their `Services`, a `ConfigMap`, a `Secret`
(optional), and one routing resource — `VirtualService`, `HTTPRoute`, or
`Ingress` — depending on `routing.type`. The chart does **not** create the
Istio Gateway, Gateway API Gateway, or cert-manager `Certificate`; those are
cluster-level concerns you supply beforehand.

#### Prerequisites

- Helm 3.x
- External PostgreSQL 15+ and Redis 7+ (connection details in values)
- A routing entry point already installed in the cluster (Istio, Gateway API
  controller, or an Ingress controller)

#### Install

```bash
helm install mxid deploy/helm/mxid \
  -n mxid --create-namespace \
  -f values-prod.yaml
```

Or pass individual overrides with `--set`:

```bash
helm install mxid deploy/helm/mxid \
  -n mxid --create-namespace \
  --set edition=ce \
  --set host=id.example.com \
  --set image.tag=v1.8.0 \
  --set database.host=pg.internal \
  --set redis.host=redis.internal \
  --set secrets.databasePassword=<db-pw> \
  --set secrets.redisPassword=<redis-pw> \
  --set secrets.cryptoKeyEncryptionKey=$(openssl rand -base64 32) \
  --set secrets.auditChainKey=$(openssl rand -base64 32) \
  --set secrets.auditAnchorKey=$(openssl rand -base64 32)
```

> The two `audit*Key` secrets are **required in release mode** (the chart's
> Secret template fails the install without them). Generate `auditChainKey`
> **once** and store it durably — changing it later invalidates the existing
> audit chain. For production, prefer `secrets.create: false` + an
> `existingSecret` created via a secret manager (see below) over `--set`.

#### Minimum production values file

Create `values-prod.yaml` with the required fields only — everything else
inherits the chart defaults:

```yaml
# values-prod.yaml — minimum required for production
edition: ce               # "ce" (ghcr.io/imkerbos/mxid) or
                          # "ee" (ghcr.io/imkerbos/mxid-ee)
host: id.example.com      # public hostname — used in routing rules

image:
  tag: "v1.8.0"           # pin a release; no "latest"

database:
  host: "pg.prod.internal"
  port: "5432"
  name: "mxid"
  user: "mxid"

redis:
  host: "redis.prod.internal"
  port: "6379"

secrets:
  # For production prefer create: false + existingSecret (see below) so no
  # plaintext secret ever lands in this file. create: true is shown here for
  # completeness.
  create: true
  databasePassword: ""            # MUST set — DB password
  redisPassword: ""               # MUST set — Redis password (empty = no auth)
  cryptoKeyEncryptionKey: ""      # MUST set — openssl rand -base64 32
  auditChainKey: ""               # MUST set — openssl rand -base64 32 (never change)
  auditAnchorKey: ""              # MUST set — openssl rand -base64 32

routing:
  type: gatewayapi                # gatewayapi (default) | istio | ingress | none
  gatewayapi:
    name: "mxid-gateway"          # existing Gateway name
    namespace: ""                 # Gateway namespace (empty = same as release)
    sectionName: ""               # optional listener, e.g. "https"

backend:
  replicaCount: 2                 # default 2 (HA); leader-elected background jobs
```

> **Do not commit `values-prod.yaml` to git if it contains plain-text secrets.**
> Use `--set` flags in CI, Sealed Secrets, External Secrets Operator, or Vault
> agent injection instead.

#### Production secrets via `existingSecret` (recommended)

Keep secrets out of Helm values entirely: create a Kubernetes Secret out of
band (via a secret manager) and reference it. The Secret **must** contain all
five keys:

```bash
kubectl create secret generic mxid-secrets -n mxid \
  --from-literal=MXID_DATABASE_PASSWORD='<db-pw>' \
  --from-literal=MXID_REDIS_PASSWORD='<redis-pw>' \
  --from-literal=MXID_CRYPTO_KEY_ENCRYPTION_KEY='<openssl rand -base64 32>' \
  --from-literal=MXID_CRYPTO_AUDIT_CHAIN_KEY='<openssl rand -base64 32>' \
  --from-literal=MXID_CRYPTO_AUDIT_ANCHOR_KEY='<openssl rand -base64 32>'
```

```yaml
# values-prod.yaml
secrets:
  create: false
  existingSecret: mxid-secrets
```

Prefer the External Secrets Operator (pulls from Vault / AWS Secrets Manager /
GCP SM) or Sealed Secrets over a manual `kubectl create secret`. When
`create: false`, the chart does NOT validate the keys — the app still
fails-closed at boot if any are missing.

#### Key values reference

| Key | Default | Purpose |
|-----|---------|---------|
| `edition` | `ce` | `ce` → backend image `ghcr.io/imkerbos/mxid`; `ee` → `ghcr.io/imkerbos/mxid-ee` |
| `host` | `id.example.com` | Public hostname used in all routing resources |
| `image.registry` | `ghcr.io/imkerbos` | Registry + namespace prefix for all images. Override to pull from a private registry / Harbor (air-gapped) — mirror `mxid`/`mxid-ee`/`mxid-web` (and `backend.waitForDeps.image` busybox) under it |
| `image.tag` | `v1.8.0` | Image tag for both backend and web (pin to a release) |
| `image.backendTag` | `""` | Optional override — pin the backend image (CE `mxid` or EE `mxid-ee`, per `edition`) independently of `tag`. Empty = use `tag` |
| `image.webTag` | `""` | Optional override — pin the web image independently of `tag`. Empty = use `tag` |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `imagePullSecrets` | `[]` | Pull-secret names for private registries (needed for `edition: ee`) |
| `backend.replicaCount` | `2` | Backend replica count (default 2 for HA); each pod gets a unique Snowflake nodeID from its ordinal. Single-writer jobs are leader-elected, so >1 is safe |
| `backend.waitForDeps.enabled` | `true` | Init container that blocks pod startup until Postgres + Redis accept TCP connections (no crash-loop while deps come up) |
| `backend.waitForDeps.image` | `busybox:1.37` | Image for the wait-for-deps init container (mirror it too for air-gapped registries) |
| `backend.autoscaling.enabled` | `false` | Enable HPA on the backend StatefulSet |
| `backend.autoscaling.minReplicas` | `1` | HPA minimum |
| `backend.autoscaling.maxReplicas` | `5` | HPA maximum |
| `web.replicaCount` | `2` | Web (nginx + SPA) replica count — stateless, any count is safe |
| `database.host` | `postgres` | PostgreSQL hostname |
| `database.port` | `5432` | PostgreSQL port |
| `database.name` | `mxid` | Database name |
| `database.user` | `mxid` | Database user |
| `redis.host` | `redis` | Redis hostname |
| `redis.port` | `6379` | Redis port |
| `secrets.create` | `true` | Create a Secret from the values below; set `false` to reference `secrets.existingSecret` instead |
| `secrets.keepOnUninstall` | `true` | When `create: true`, annotate the Secret `helm.sh/resource-policy: keep` so `helm uninstall` does NOT delete it (protects the KEK + audit-chain key). The kept Secret retains Helm ownership metadata, so a same-name/same-namespace reinstall adopts it (no "already exists" error) |
| `secrets.preserveExisting` | `true` | When `create: true`, make the Secret idempotent: if it already exists, reuse its per-key values instead of overwriting from `values`. A reinstall/upgrade (incl. after an uninstall that kept the Secret) never clobbers the existing KEK / audit-chain key. Set `false` to force `values` to win (e.g. to rotate a password) |
| `secrets.existingSecret` | `""` | Name of a pre-existing Secret (requires keys `MXID_DATABASE_PASSWORD`, `MXID_REDIS_PASSWORD`, `MXID_CRYPTO_KEY_ENCRYPTION_KEY`, `MXID_CRYPTO_AUDIT_CHAIN_KEY`, `MXID_CRYPTO_AUDIT_ANCHOR_KEY`) |
| `secrets.databasePassword` | `""` | DB password (used when `secrets.create: true`) |
| `secrets.redisPassword` | `""` | Redis password (empty = no auth) |
| `secrets.cryptoKeyEncryptionKey` | `""` | Master KEK — `openssl rand -base64 32` |
| `secrets.auditChainKey` | `""` | Audit hash-chain HMAC key — `openssl rand -base64 32`; **generate once, never change** |
| `secrets.auditAnchorKey` | `""` | Audit anchor Ed25519 seed — `openssl rand -base64 32`; required when `audit.anchorSink.enabled` |
| `audit.anchorSink.enabled` | `true` | Persist signed external audit anchors to a per-pod PVC (StatefulSet `volumeClaimTemplates`) |
| `routing.type` | `gatewayapi` | Routing backend: `gatewayapi` (default), `istio`, `ingress`, or `none` |
| `routing.forwardedProtoHttps` | `true` | Force `X-Forwarded-Proto: https` on backend routes (gatewayapi HTTPRoute filter / istio VirtualService header). **CRITICAL behind a TLS-terminating Gateway/LB: without this header the OIDC (zitadel) engine sees `scheme=http`, mismatches the https issuer URL, and rejects discovery/authorize with HTTP 403.** Ingress controllers usually inject the header themselves. Set `false` only if your edge already forwards a trustworthy `X-Forwarded-Proto` |
| `routing.gke.healthCheck.enabled` | `false` | GKE Gateway API only: emit a `HealthCheckPolicy` pointing the Google Cloud LB health check at `/health` (the LB default probes `/` → 404 → backend marked unhealthy). Keep disabled off GKE (the CRD won't exist) |
| `config.serverMode` | `release` | `release` or `debug` |
| `config.allowedOrigins` | `""` | CORS allow-list; defaults to `https://<host>` when empty |
| `config.trustedProxies` | `[]` | Trusted reverse-proxy / LB CIDRs (rendered as `MXID_SERVER_TRUSTED_PROXIES`). Set to your edge proxy CIDR(s) so the real client IP is taken from `X-Forwarded-For`; empty falls back to a broad RFC1918 default with a release-mode warning. See *Reverse proxy headers* |
| `config.formFillExtension` | `false` | Form-fill SSO browser extension (EE `form_fill`): allow-lists the extension origin and sets the portal cookie `SameSite=None`. Enable only when rolling out the extension |
| `config.issuerUrl` | `""` | Canonical OIDC issuer / SAML EntityID base / CAS root. Empty = derived as `https://<host>`; set explicitly for split-domain deployments |
| `config.portalUrl` | `""` | Canonical portal URL. Empty = `https://<host>` |
| `config.consoleUrl` | `""` | Canonical console URL. Empty = `https://<host>/admin` |

#### Ingress routing options (choose one)

The chart renders exactly one routing resource based on `routing.type`. It does
not provision a Gateway or Ingress controller — point it at one you already have.

**Istio — VirtualService**

The chart renders a `VirtualService` that splits traffic by path: `/api`,
`/protocol`, `/static`, and `/health` go to the backend `Service`; everything
else goes to the web `Service`. Reference your existing `Gateway`:

```yaml
routing:
  type: istio
  istio:
    gateway: "istio-system/mxid-gateway"   # namespace/name of existing Gateway
```

**Kubernetes Gateway API — HTTPRoute**

```yaml
routing:
  type: gatewayapi
  gatewayapi:
    name: "mxid-gateway"
    namespace: "istio-system"   # namespace of the existing Gateway resource
    sectionName: ""             # optional — target a specific listener
```

**Standard Ingress**

```yaml
routing:
  type: ingress
  ingress:
    className: "nginx"
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    tls:
      enabled: true
      secretName: "mxid-tls"   # cert-manager or manually provisioned Secret
```

#### CE → EE upgrade (zero downtime)

Switch editions with a single `helm upgrade`. The chart replaces the backend
image; Kubernetes performs a rolling update — new EE pods start before old CE
pods terminate:

```bash
helm upgrade mxid deploy/helm/mxid --reuse-values --set edition=ee
```

The license stored in the database is picked up automatically — no
re-activation needed. EE code-separated features (`external_idp`, `webauthn`,
`scim`, …) register themselves on startup. To roll back:

```bash
helm rollback mxid
```

#### StatefulSet and Snowflake nodeID

The backend is deployed as a `StatefulSet`. Each pod's Snowflake nodeID is
derived automatically from its ordinal index (pod-0 → nodeID 0, pod-1 →
nodeID 1, …), guaranteeing uniqueness across replicas without any extra
coordination. There are **no `volumeClaimTemplates`** — the backend has no
local state (icons are stored in the database). To scale horizontally, increase
`backend.replicaCount` or enable HPA via `backend.autoscaling`.

#### TLS / HTTPS configuration

How you terminate TLS depends on the routing mode in use.

**Ingress mode**

Set `routing.ingress.tls.enabled=true` and `routing.ingress.tls.secretName`
to the name of a Kubernetes TLS Secret. Two ways to provision the Secret:

**(a) cert-manager (recommended)** — add the cluster-issuer annotation and
cert-manager will automatically create and renew the Secret:

```yaml
routing:
  type: ingress
  ingress:
    className: "nginx"
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    tls:
      enabled: true
      secretName: "mxid-tls"   # cert-manager creates and renews this Secret
```

**(b) Manual** — create the Secret yourself before installing the chart, then
reference it with the same `secretName`:

```bash
kubectl create secret tls mxid-tls \
  --cert=fullchain.pem \
  --key=privkey.pem \
  -n mxid
```

**Istio mode / Gateway API mode**

The chart does **not** create a Gateway. TLS is terminated on the listener of
your **existing Gateway** — the `VirtualService` (Istio) or `HTTPRoute`
(Gateway API) that the chart renders handles only L7 HTTP routing. HTTPS is
therefore configured entirely in your Gateway:

- *Istio*: configure the `tls` stanza on the relevant `Gateway` listener.
- *Gateway API*: configure `listeners[].tls` on the `Gateway` resource.

No TLS settings are needed — or should be set — on the chart side for these
two modes.

#### Graceful shutdown (zero request loss during rolling updates, scale-down, and HPA events)

Both the backend and the web (nginx) pods include a `preStop` hook and a
`terminationGracePeriodSeconds` setting to avoid dropping in-flight requests
during pod termination.

**Why this matters.** When Kubernetes terminates a pod it sends `SIGTERM` and
begins removing the pod from Service endpoints simultaneously. Because endpoint
propagation through kube-proxy and the mesh takes a few seconds, new requests
can still be routed to the pod after `SIGTERM` arrives. The `preStop` hook
inserts a sleep *before* `SIGTERM` is delivered, giving the data-plane time to
drain the endpoint. After the hook completes, the backend receives `SIGTERM`
and drains any remaining in-flight requests (~10 s) before exiting.

**Values that control this behaviour:**

| Value | Default | Purpose |
|-------|---------|---------|
| `backend.preStopSleep` | `5` | Seconds the backend pod sleeps in `preStop` before `SIGTERM` is sent. Set to `0` to disable the hook. |
| `backend.terminationGracePeriodSeconds` | `40` | Must be greater than `preStopSleep + 10` to give the backend time to finish draining after `SIGTERM`. |
| `web.preStopSleep` | `5` | Same hook on the nginx pod. Set to `0` to disable. |
| `web.terminationGracePeriodSeconds` | `30` | Grace period for the nginx pod. |

Example — increasing the sleep for a high-traffic environment:

```yaml
backend:
  preStopSleep: 10
  terminationGracePeriodSeconds: 60   # > preStopSleep (10) + drain time (10)

web:
  preStopSleep: 10
  terminationGracePeriodSeconds: 45
```

## Reverse proxy headers

MXID trusts `X-Forwarded-For` + `X-Forwarded-Proto` only when configured to do so:

```yaml
server:
  trusted_proxies:
    - 127.0.0.1
    - 10.0.0.0/8
```

The same setting is available as the env var `MXID_SERVER_TRUSTED_PROXIES`
(comma-separated CIDRs) and, on Kubernetes, as the chart value
`config.trustedProxies`. Set it to your edge proxy / LB CIDR(s) so the app
resolves the real client IP from `X-Forwarded-For` — otherwise every intranet
client collapses onto the LB IP, which breaks per-client audit, rate limiting,
and conditional access.

Your TLS-terminating proxy **must forward `X-Forwarded-Proto: https`** to the
backend — the OIDC engine compares the request scheme against the https issuer
URL and rejects discovery/authorize with 403 when it sees plain `http` (on the
Helm chart this is `routing.forwardedProtoHttps: true`, on by default).

If the proxy doesn't add these headers, leave `trusted_proxies` empty so MXID treats the proxy IP as the client IP.

## Production checklist

- [ ] HTTPS everywhere. Set `server.cookie_secure: true`.
- [ ] `server.cookie_domain` set if the portal + console are on subdomains of the same parent.
- [ ] `MXID_CRYPTO_KEY_ENCRYPTION_KEY` + DB / Redis passwords are strong, unique, and private (not dev placeholders).
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
- [ ] **(Kubernetes)** Each backend replica has a unique `MXID_SNOWFLAKE_NODE_ID` (use StatefulSet ordinal or Redis lease).
- [ ] **(Kubernetes)** Liveness probe → `/health`; readiness probe → `/readyz` (dependency-aware).
- [ ] **(Kubernetes)** After a logical PostgreSQL restore (`pg_dump` → new cluster), re-activate the EE license — `system_identifier` changes.

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
- Request ID propagation via `X-Request-Id` header; error responses carry a
  `traceId` field — ask users to quote it and grep the logs.
- `/health` — liveness (process alive, no dependency check). `/readyz` —
  readiness (pings DB + Redis, `503` when either is down).
- `/metrics` — Prometheus metrics (HTTP requests, background workers, build
  info). **Security: keep `/metrics` internal-only** — do not route it through
  the public ingress/nginx; scrape it from inside the network/cluster only.
- Audit log is the primary security-relevant signal — query the `mxid_audit_log` table or wire up the alert webhook.

## Private registry (the usual case)

The cluster can't pull from `ghcr.io` — either there's no route, or the
Enterprise image is a private package. But if **one machine** can reach both
`ghcr.io` and your registry (your laptop, a jump box, a CI runner), that's all
you need. Mirror the images once per release, then upgrade with Helm normally.

The whole upgrade is two steps: **mirror the images, then point Helm at the new
tag.**

```bash
docker login ghcr.io                     # once — the EE image is private
docker login harbor.internal             # once

# step 1 — mirror. Either form; the make target is a two-line wrapper around
# the script, so use the script directly if the machine has no make/checkout.
make sync-images TAG=v1.8.0 REGISTRY=harbor.internal/mxid    # add EDITION=ce for CE
./scripts/sync-images.sh v1.8.0 harbor.internal/mxid         # identical
```

That pulls the backend, the web image and `busybox` (the chart's `waitForDeps`
init container — miss it and every pod sits in `Init:ImagePullBackOff`), retags
them under your prefix and pushes. Repo names must stay `mxid` / `mxid-ee` /
`mxid-web` / `busybox`, since the chart appends exactly those to
`image.registry`.

Step 2 — upgrade. The script prints this command with your values filled in:

```bash
helm upgrade --install mxid deploy/helm/mxid -n mxid -f values.yaml \
  --set image.registry=harbor.internal/mxid \
  --set image.tag=v1.8.0 \
  --set edition=ee \
  --set backend.waitForDeps.image=harbor.internal/mxid/busybox:1.37
```

Keep `values.yaml` in your own config repo and edit it once; **later upgrades
only change the version** — re-run step 1 with the new `TAG`, then step 2 with
the same `--set image.tag`. Everything else stays put.

`busybox` is only the `waitForDeps` init container. If you already have one in
your registry, point `backend.waitForDeps.image` at it instead; or set
`backend.waitForDeps.enabled=false` to drop it entirely (the backend then
crash-loops a few times while Postgres/Redis come up, rather than waiting).

Harbor note: create the project first — Harbor does not auto-create one on
push, and the error is unhelpful.

Any OCI registry works (Harbor, Nexus, ECR, a plain `registry:2`).

### Building from source instead of pulling

Same two-step flow, but step 1 builds the images from source. Use it when the
released images can't be pulled at all, when you carry local patches, or when
policy requires building from reviewed source.

```bash
make build-images TAG=v1.8.0 REGISTRY=harbor.example.com/sa02      # EDITION=ce for CE
./scripts/build-images.sh v1.8.0 harbor.example.com/sa02           # identical
```

It clones what's missing at the requested tag, updates an existing git checkout
to that tag, and builds a ZIP extract as-is (GitHub ZIPs have no `.git`, so
extract and rename the folders to exactly `mxid` and `mxid-ee` — the go.mod
`replace => ../mxid` and the EE Dockerfile's `COPY` depend on those names).
Authentication is yours to arrange: `gh auth login` or an SSH URL via
`MXID_EE_REPO` for the private EE repo, and `podman login` / `docker login`
for the registry. podman is preferred when installed.

The EE backend needs both trees side by side because its `go.mod` replaces the
CE module with `../mxid`, and it is built with `garble` — slow, and **amd64
only**, since obfuscating the whole dependency tree under arm64 emulation is
impractical. The web image is shared by both editions (edition is a runtime
gate via `/system/info`), so an EE build produces `mxid-ee` + `mxid-web`.

Run it from inside a CE checkout and it builds that working tree as-is rather
than checking out `TAG` — it will not swap the source out from under itself.

## Fully air-gapped install / upgrade

Only when **no** machine can reach both `ghcr.io` and your registry. Otherwise
use `sync-images` above — it is one command instead of bundle / carry / unpack /
install. This path ships one tarball you carry in by hand.

**On a machine that can reach ghcr.io** (`docker login ghcr.io` first for EE):

```bash
make offline-bundle TAG=v1.8.0             # EE; add EDITION=ce for Community
# -> mxid-offline-ee-v1.8.0.tar.gz  (~80-200 MB)
```

The bundle contains all three images the chart needs, the packaged Helm chart, a
values template and `SHA256SUMS`. The third image is easy to forget and fatal to
omit: `busybox`, used by the `waitForDeps` init container — without it every pod
sits in `Init:ImagePullBackOff`.

**At the site — first install:**

```bash
tar xzf mxid-offline-ee-v1.8.0.tar.gz && cd mxid-offline
mkdir -p /opt/mxid && cp values.example.yaml /opt/mxid/values.yaml
$EDITOR /opt/mxid/values.yaml          # URLs, datastores, secrets
./install.sh --registry harbor.internal/mxid --values /opt/mxid/values.yaml
```

**Every upgrade after that:**

```bash
tar xzf mxid-offline-ee-v1.9.0.tar.gz    # same mxid-offline/ directory
cd mxid-offline && ./install.sh
```

Every bundle unpacks to `mxid-offline/` regardless of version — the tarball
carries the version so you can tell releases apart and keep one for rollback,
but the path never changes, so runbooks and scripts don't hardcode a version.
Extracting a newer bundle over the old directory is the intended flow;
`install.sh` selects the chart from `manifest.env`, so a leftover file from a
previous version is never picked up.

No flags, no re-editing. Keep `values.yaml` **outside** the bundle directory:
bundles are disposable and get replaced each release, your site config is not.
On a successful install the registry, namespace, release name and values path
are recorded in `site.conf` (`/etc/mxid/site.conf`, else `~/.config/mxid/`),
and later runs read them back. If that file is ever lost, the settings are
recovered from the deployed Helm release instead. An explicit flag always wins,
so overriding one thing for one run costs nothing.

Any OCI registry works — Harbor, Nexus, ECR, a plain `registry:2`. The bundled
images carry their original `ghcr.io/...` names (that is just what `docker save`
records); `install.sh` retags them under whatever `--registry` you give. Two
Harbor-specific notes: `docker login` first, and **create the project
beforehand** — Harbor does not auto-create one on push, and the resulting error
is unhelpful.

`install.sh` verifies checksums, loads the images into docker / nerdctl / ctr,
retags and pushes them under your registry prefix, then runs `helm upgrade
--install` with `image.registry` and `backend.waitForDeps.image` pointed at it.
Add `--dry-run` to rehearse. Repo names must stay `mxid` / `mxid-ee` /
`mxid-web` / `busybox` under your prefix — the chart's helpers append exactly
those names.

Before pushing anything it validates the values file, because the chart fails
closed on missing secrets: `databasePassword`, `cryptoKeyEncryptionKey`,
`auditChainKey` and `auditAnchorKey` are all required (the last one because
`audit.anchorSink.enabled` defaults to `true` — set it to `false` if you don't
want anchoring). Generate each with `openssl rand -base64 32`, and **back them
up**: losing `cryptoKeyEncryptionKey` makes every stored secret unrecoverable.

If there is genuinely no internal registry, `./install.sh --load-only` imports
the images into the local runtime — but you must run it on **every** node, set
`image.pullPolicy=IfNotPresent`, and repeat it for any node added later. A
registry is strongly preferred.

Upgrades are the same command with a newer bundle. To roll back, re-run the
previous version's bundle; images are never tagged `latest`, so the version you
pin is the version you get.

## Upgrade

1. Read [CHANGELOG.md](../CHANGELOG.md) for the target version's notes.
2. Back up the database (`pg_dump`).
3. Pull the new tag, rebuild, restart. Migrations run on startup.
4. Verify the integration playbooks under console `/docs` still pass for your critical SPs.

> **Upgrading from < v1.7.2:** v1.7.2 fixed SPA cache headers — `index.html` is
> now served with `Cache-Control: no-cache` (always revalidated) while the
> hashed `/assets/*` stay immutable, so future upgrades roll out cleanly.
> Browsers that cached a pre-v1.7.2 `index.html` may still show the old SPA
> once — have users hard-refresh (Ctrl/Cmd+Shift+R) a single time after the
> upgrade; from then on it is automatic.

## Troubleshooting

| Symptom | Probable cause | Fix |
|---------|----------------|-----|
| OIDC token has `iss` = `http://localhost:10050` | `ExternalURLs.IssuerURL` empty + `config.IssuerURL` is localhost | Set `ExternalURLs.IssuerURL` in console settings. |
| CAS app returns `application not found` | App `code` mismatch | `/protocol/cas/<code>/login` path segment is the DB `code` column. |
| Toast "已保存" not visible after settings save | Monorepo Tailwind `@source` lost | Verify `web/apps/<app>/src/index.css` has `@source "../../../packages/shared/src/**/*.{ts,tsx}"`. |
| Login redirect loop in portal | Cookie domain mismatch | Set `server.cookie_domain` to the shared parent domain. |
