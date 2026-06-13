# Editions — Community (CE) vs Enterprise (EE)

MXID ships as an open-core product. **Community Edition (CE)** is the default and
fully usable on its own. **Enterprise Edition (EE)** unlocks additional features
with a signed license.

## Feature matrix

| Capability | CE | EE |
|------------|:--:|:--:|
| Password login, sessions, TOTP MFA | ✅ | ✅ |
| OIDC / SAML / CAS / JWT protocols | ✅ | ✅ |
| Users / orgs / groups, RBAC | ✅ | ✅ |
| SMTP email, basic audit | ✅ | ✅ |
| **Single default tenant** | ✅ | ✅ |
| **Multi-tenant** (more than the default tenant) | ❌ | ✅ |
| **External IdP login** (social / enterprise SSO) | ❌ | ✅ |
| **Branding / white-label** (logo, colors, login page) | ❌ | ✅ |
| Conditional access, WebAuthn/passkeys, SCIM, SMS, advanced step-up | ❌ | ✅ |

Feature keys (in the license payload): `multi_tenant`, `external_idp`,
`branding`, `conditional_access`, `webauthn`, `scim`, `advanced_stepup`, `sms`.

## How editions are built (architecture)

Three repositories, single source of truth, no fork:

```
github.com/imkerbos/mxid            public   CE product + app.Run() + pkg/ee/{license,registry}
github.com/imkerbos/mxid-ee         private  EE features; wraps app.Run(), garble-obfuscated
github.com/imkerbos/license-authority  private  per-product Ed25519 signing keys + issuance
```

Two layers of EE gating:

1. **Runtime-gated** (`multi_tenant`, `external_idp`, `branding`): the code lives
   in the CE binary but `middleware.RequireFeature` / `license.Current().Has()`
   returns 403 / locks the UI unless the license grants the feature.
2. **Code-separated** (high-value features, e.g. SCIM): the implementation lives
   ONLY in `mxid-ee`. EE feature packages register into `pkg/ee/registry` from
   their `init()`; the CE binary imports none, so the code is *physically absent*
   from it — there is nothing to patch out. Verified: the CE binary contains zero
   EE symbols. The EE binary is built with `garble` (symbol + control-flow
   obfuscation) as a further anti-tamper measure.

The license signature is the hard control: it is verified against an embedded
Ed25519 **public** key, so an operator cannot forge or edit a license. The
private signing key lives only in `license-authority`.

## Running CE

CE images are public on GHCR:

```
ghcr.io/imkerbos/mxid       # backend
ghcr.io/imkerbos/mxid-web   # nginx + SPAs (shared by both editions)
```

`.env` (see [DEPLOYMENT.md](DEPLOYMENT.md)) with `MXID_TAG` set and **no**
`MXID_LICENSE`, then `docker compose up -d`. No license → CE.

## Running EE

The EE backend is a separate, **private** image (`ghcr.io/imkerbos/mxid-ee`,
garble-obfuscated). The web image is shared with CE. Select it via the EE
compose overlay in `.env`:

```ini
# external DB:
COMPOSE_FILE=deploy/compose/docker-compose.yml:deploy/compose/docker-compose.ee.yml
# self-contained (containerized Postgres + Redis):
# COMPOSE_FILE=deploy/compose/docker-compose.yml:deploy/compose/docker-compose.standalone.yml:deploy/compose/docker-compose.ee.yml

MXID_TAG=v0.0.2
MXID_LICENSE=<signed token>     # see "Activation" below
```

```bash
docker login ghcr.io            # EE image is private — needs a read:packages token
docker compose pull
docker compose up -d
```

> Running an EE license on the CE (`mxid`) image still unlocks the *runtime-gated*
> features (branding / multi-tenant / external IdP), but NOT the code-separated
> ones — those exist only in the `mxid-ee` image. EE customers run `mxid-ee`.

## Activation

A license is an Ed25519-signed token issued by `license-authority`:

```bash
# in the license-authority repo
go run ./cmd/sign -product mxid \
  -customer "Acme Corp" -features all -exp 2027-01-01 -max-tenants 50
```

Provide the token to a running instance in either of two ways:

- **Env** — set `MXID_LICENSE=<token>` in `.env` and restart. Read at boot.
- **Console** — Settings → License: paste the token and save. Verified, edition
  flips immediately (hot-reload), no restart. Recommended — it also persists the
  derived limits used for quota enforcement.

The console License page shows the resolved edition, customer, expiry, and
unlocked features. Only the token is editable; everything else is derived from
the verified signature.

`GET /api/v1/system/info` exposes `edition` + `features`; the frontend gates EE
UI on these (e.g. the branding page is locked with an upsell banner in CE).

## Limits & enforcement

| Limit | Source | Enforced |
|-------|--------|----------|
| Feature set | signed `features[]` | ✅ route gates + UI + (for code-separated) absence from the CE binary |
| Expiry | signed `exp` | ✅ expired token → verification fails → falls back to CE |
| Product binding | signed `product` | ✅ a license for another product is rejected |
| Max tenants / users | signed `max_tenants` / `max_users` | ✅ via the License setting (use console activation so the quota is persisted) |

Offline by design: there is no online revocation. Bound risk with `-exp` and
renewal — an expired license silently degrades to CE.

## Issuing licenses (vendor)

See the `license-authority` repo: `cmd/keygen` (one key pair per product, public
half embedded in the product), `cmd/sign` (issue a token), `products/<id>.yaml`
(feature catalog), `customers/` (issuance records). Private keys never leave the
authority repo / secrets manager.
