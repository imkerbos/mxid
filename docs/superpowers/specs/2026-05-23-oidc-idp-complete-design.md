# OIDC Identity Provider — Complete Vertical Design

**Status**: Draft for approval
**Date**: 2026-05-23
**Owner**: Backend + Frontend
**Standard**: Commercial-grade EIAM, benchmarked against Keycloak / Auth0 / Okta / TopIAM

## 1. Goal & Scope

Stand up MXID's OIDC Identity Provider as a fully spec-compliant, production-grade vertical, delivered in three staged milestones (A → B → C). Each milestone is independently testable; A unblocks happy-path SSO, B unlocks enterprise deployment, C unlocks OIDC Conformance certification.

### 1.1 Non-Goals

- Multi-tenant key isolation in A/B (single global issuer; schema reserves `tenant_id`)
- SAML / CAS / JWT / FORM protocols (separate spec)
- Social login (LDAP/OAuth identity sources) — separate spec
- MFA enrollment (separate spec)

## 2. Milestones

### Milestone A — Happy Path (1 sprint)

**Outcome**: A sample relying party can complete an end-to-end OIDC authorization_code flow against MXID and receive a valid id_token + access_token + userinfo.

In scope:
- RSA-2048 signing key auto-generation per OIDC application (transactional with app create)
- Login → protocol session bridge (`mxid_proto_sid` cookie + Redis session)
- `client_secret_basic` / `client_secret_post` / `none` (PKCE only) auth methods
- Authorization code flow with PKCE (S256 only — `plain` rejected)
- ID token + Access token as JWT-RS256, opaque code & refresh
- Standard scopes: `openid` `profile` `email` `phone` `groups` `offline_access`
- IdP-level JWKS endpoint aggregating all active public keys
- Console application CRUD UI with quickstart code samples (curl / Go / Node)
- Portal application library page with one-click navigation
- Sample relying parties: curl script, Go binary, Node Express
- Integration test suite covering full code flow

Out of scope (deferred):
- Consent screen (always skipped via `require_consent=false` default)
- Back-channel logout
- Refresh token rotation
- `client_secret_jwt` / `private_key_jwt` / `tls_client_auth`
- Hybrid flow / Implicit flow / Device flow
- Dynamic client registration
- Pairwise subject

### Milestone B — Production Compliance (2 sprints)

**Outcome**: MXID can be deployed to production for enterprise self-hosting; passes a typical enterprise security audit.

Adds to A:
- Consent screen + `mxid_user_app_consent` persistence
- Per-app custom claims mapping (Keycloak "Mappers" equivalent)
- Back-channel logout (RP-initiated logout propagated to all RPs)
- Refresh token rotation with reuse detection
- `client_secret_jwt` + `private_key_jwt` client authentication
- Soft signing-key rotation (multi-key JWKS with `active` / `rotating` / `retired` states)
- Token revocation strengthened (introspection + revocation list)
- "Remember Me" persistent session option
- Per-app token lifetime overrides
- `prompt=consent` parameter support
- Comprehensive audit logging for all token events
- Per-app rate limiting

### Milestone C — OIDC Certified (3–4 sprints)

**Outcome**: MXID passes the OpenID Foundation Conformance Suite test cases for OP Basic + OP Implicit + OP Hybrid + OP Logout profiles.

Adds to B:
- Hybrid flow (`code id_token`, `code token`, `code id_token token` response types)
- Dynamic Client Registration (RFC 7591) + management protocol (RFC 7592)
- `tls_client_auth` + `self_signed_tls_client_auth` (FAPI / mTLS)
- Pairwise subject_type support
- `prompt=select_account` (account picker for multi-account users)
- Front-channel logout
- Session management endpoint (`check_session_iframe`)
- Request object support (`request` / `request_uri` parameters)
- Multi-tenant signing key isolation
- OIDC Conformance Suite CI integration

## 3. Architecture Overview

### 3.1 Components

```
┌──────────────────────────────────────────────────────────────┐
│                       Browser (RP UA)                        │
└──────────┬──────────────────────┬────────────────────────────┘
           │                      │
           │  redirect to         │  callback with code
           │  /protocol/oidc/     │
           │  authorize           │
           ▼                      ▼
┌──────────────────────────────────────────────────────────────┐
│                  MXID Backend (cmd/server)                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │           Gateway Layer (internal/gateway)             │  │
│  │  console.LoginHandler / portal.LoginHandler            │  │
│  │  ─ writes mxid_portal_sid OR mxid_console_sid          │  │
│  │  ─ writes mxid_proto_sid    (NEW — A milestone)        │  │
│  │  ─ writes to Redis: session:portal:* / session:proto:* │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │       Protocol Layer (internal/protocol/oidc)          │  │
│  │  handler.go                                            │  │
│  │  ├─ discovery        ── reads issuer + supported algs  │  │
│  │  ├─ authorize        ── reads mxid_proto_sid           │  │
│  │  ├─ token            ── code → JWT(id+access)+refresh  │  │
│  │  ├─ userinfo         ── access_token → claims          │  │
│  │  ├─ jwks             ── IdP-level aggregate            │  │
│  │  ├─ revoke           ── invalidate refresh/access      │  │
│  │  ├─ introspect       ── token metadata                 │  │
│  │  └─ end-session      ── delete proto_sid + RP notify   │  │
│  │  token.go            ── JWT signing / verification     │  │
│  │  store.go            ── Redis backed code/refresh      │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │      Resolver Layer (internal/protocol/resolver)       │  │
│  │  AppResolver  IdentityResolver  SessionResolver        │  │
│  │  ─ Decouples protocol handlers from domain repos       │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │            Domain Layer (internal/domain)              │  │
│  │  app: App + AppCert + KeyService (NEW)                 │  │
│  │  authn: SessionService (extended)                      │  │
│  │  user: UserRepo + UserClaimsAssembler (NEW)            │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
           │                      │
           ▼                      ▼
       PostgreSQL              Redis
       ─ mxid_app              ─ session:portal:{sid}
       ─ mxid_app_cert         ─ session:console:{sid}
       ─ mxid_user             ─ session:proto:{sid}
       ─ mxid_user_group       ─ oidc:code:{code}
                               ─ oidc:refresh:{hash}
                               ─ oidc:access_jti:{jti}
```

### 3.2 Trust Boundaries

| Boundary | Mechanism |
|---|---|
| Browser ↔ MXID gateway | HTTPS + HttpOnly + Secure + SameSite=Lax cookies |
| RP backend ↔ MXID token endpoint | `client_secret_basic` / `client_secret_post` / mTLS (C) |
| RP ↔ MXID JWKS | Public; verifies id_token / access_token offline |
| MXID backend ↔ DB | TLS (prod); credentials from env / Vault |
| MXID backend ↔ Redis | Network ACL + password auth (prod) |

## 4. Session Bridge (Milestone A core)

### 4.1 Cookies

| Cookie | Path | HttpOnly | Secure | SameSite | TTL | Purpose |
|---|---|---|---|---|---|---|
| `mxid_portal_sid` | `/` | yes | prod=yes / dev=no | Lax | session (browser) | Portal SPA session |
| `mxid_console_sid` | `/` | yes | prod=yes / dev=no | Lax | session | Console SPA session |
| `mxid_proto_sid` | `/` | yes | prod=yes / dev=no | Lax | session | Protocol SSO session shared by OIDC/SAML/CAS |

Each cookie value is 32 bytes of cryptographic randomness, base64url-encoded, server-side opaque.

### 4.2 Redis Schema

```
mxid:session:portal:{sid}    → JSON  { user_id, login_time, ip, ua, expires_at }    TTL 30m idle / 8h abs
mxid:session:console:{sid}   → JSON  { same as portal }                              TTL 30m idle / 8h abs
mxid:session:proto:{sid}     → JSON  { user_id, login_time, auth_methods[],
                                       remembered_apps[], expires_at }                TTL 8h idle / 24h abs
```

Idle TTL is refreshed on each access; absolute TTL is the hard cap from login moment.

### 4.3 Lifecycle Rules

- **Login success** (`POST /api/v1/{portal,console}/auth/login`): write SPA cookie + `mxid_proto_sid` + both Redis entries in a single transaction-equivalent unit (one Redis MULTI block).
- **Logout from SPA** (`POST /api/v1/{portal,console}/auth/logout`): delete SPA cookie + Redis SPA key only. `mxid_proto_sid` is preserved per OIDC spec — SPA logout ≠ SSO logout.
- **OIDC `end_session_endpoint`**: delete `mxid_proto_sid` + Redis proto key. Triggers back-channel logout to RPs in B milestone.
- **Cookie value mismatch with Redis**: treat as unauthenticated, return 401, do not auto-renew.

### 4.4 `prompt` Parameter Behavior

| prompt | Has proto session | No proto session |
|---|---|---|
| (empty) | Use session, issue code | Redirect to login |
| `none` | Issue code if consent OK, else `interaction_required` | Return `login_required` error |
| `login` | Force re-auth, ignore session | Redirect to login |
| `consent` | (B) Force consent screen | Login + consent |
| `select_account` | (C) Show account picker | Login |

A milestone implements: empty, `none`, `login`.

## 5. Signing Key Management (Milestone A core)

### 5.1 Per-Application RSA Keypairs

Each OIDC application owns its own signing keypair stored in `mxid_app_cert`. JWKS endpoint aggregates public keys across all apps at the IdP level so RPs see a single key set.

### 5.2 Algorithms by Milestone

| Milestone | Algorithm | Key Size |
|---|---|---|
| A | RS256 | RSA 2048 |
| B | + RS384 / RS512 | RSA 2048–4096 |
| C | + ES256 / ES384 / EdDSA | EC P-256 / Ed25519 |

A enforces RS256 + RSA-2048 to align with OIDC default and minimum recommended size.

### 5.3 Key Encryption at Rest

- Master key loaded from env var `MXID_KEY_ENCRYPTION_KEY` (32 bytes, base64-encoded)
- AES-256-GCM encrypts the private key PEM before persistence
- Stored field format: `base64(nonce || ciphertext || tag)`
- Server fails fast on startup if env var missing or invalid
- A milestone: env-only; B milestone: pluggable `KeyProvider` interface for Vault / AWS KMS / GCP KMS

### 5.4 Bootstrap Flow

1. Admin creates OIDC application via console
2. Service layer persists `mxid_app` row
3. Same unit of work calls `KeyService.GenerateForApp(appID)`:
   - `crypto/rsa.GenerateKey(rand.Reader, 2048)`
   - AES-GCM encrypt private PEM
   - Insert `mxid_app_cert` row with `status=1 active`, `kid=ULID()`, `not_before=now`, `not_after=now+1y`
4. On failure, entire transaction rolls back; no orphan app rows

### 5.5 JWKS Endpoint

`GET /protocol/oidc/jwks` returns a JWK Set composed of every `status IN (active, rotating)` cert across all enabled apps. Each entry includes `kid`, `kty=RSA`, `alg=RS256`, `use=sig`, `n`, `e`. Cached in-memory with 5-minute TTL invalidated on key rotation events.

### 5.6 Rotation (Milestone B)

- `POST /api/v1/console/apps/:id/rotate-signing-key`
- Generates new keypair with `status=2 rotating`
- JWKS publishes both old `active` and new `rotating` keys
- 24h later (configurable), promotion job: rotating → active, old active → retired
- Retired keys removed from JWKS after `id_token_lifetime` + grace period

## 6. Token Specification (Milestone A core)

### 6.1 Token Types

| Token | Format | Storage | Lifetime |
|---|---|---|---|
| Authorization Code | opaque 32 bytes base64url | Redis, single-use | 10 minutes |
| ID Token | JWT RS256 | Stateless (signed) | 1 hour |
| Access Token | JWT RS256 | Stateless + `jti` marker in Redis | 1 hour |
| Refresh Token | opaque 64 bytes base64url | Redis (SHA-256 hash only) | 30 days |

Rationale for JWT access token: aligns with Auth0 / Keycloak / Okta defaults; resource servers verify locally via JWKS without per-request IdP introspection. Trade-off (no immediate revocation) addressed in B via introspection + `jti` blocklist.

### 6.2 ID Token Claims

Always present:
```json
{
  "iss": "<issuer>",
  "sub": "<user_id>",
  "aud": "<client_id>",
  "exp": 1234567890,
  "iat": 1234567890,
  "auth_time": 1234567890,
  "nonce": "<from-request>",
  "at_hash": "<half-hash-of-access-token>"
}
```

Scope-gated additions:

| Scope | Claims |
|---|---|
| `profile` | `name`, `preferred_username`, `picture`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `phone` | `phone_number`, `phone_number_verified` |
| `groups` | `groups` (array of group names) |

`address` and `roles` / `organization` deferred to B.

### 6.3 Access Token Claims

```json
{
  "iss": "<issuer>",
  "sub": "<user_id>",
  "aud": "<client_id>",
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "<ULID>",
  "client_id": "<client_id>",
  "scope": "openid profile email",
  "token_type": "Bearer"
}
```

### 6.4 Authorization Code

```
mxid:oidc:code:{code} = {
  client_id, user_id, redirect_uri, scope,
  nonce, code_challenge, code_challenge_method,
  session_sid, issued_at, expires_at
}
TTL 600 seconds; deleted on first use.
```

### 6.5 Refresh Token

```
mxid:oidc:refresh:{sha256(token)} = {
  client_id, user_id, scope, session_sid,
  issued_at, expires_at, rotation_id (B)
}
TTL = refresh_token_lifetime; plaintext never stored.
```

## 7. Client / Application Model

### 7.1 Client Types

| Type | OIDC class | Has secret | PKCE | Grants |
|---|---|---|---|---|
| `web_app` | confidential | yes | optional | authorization_code, refresh_token |
| `spa` | public | no | required | authorization_code (PKCE), refresh_token |
| `native` | public | no | required | authorization_code (PKCE), refresh_token |
| `m2m` | confidential | yes | n/a | client_credentials |

### 7.2 `mxid_app` Field Extensions (A milestone)

```sql
ALTER TABLE mxid_app ADD COLUMN client_id           VARCHAR(64)  NOT NULL UNIQUE;
ALTER TABLE mxid_app ADD COLUMN client_type         VARCHAR(20)  NOT NULL DEFAULT 'web_app';
ALTER TABLE mxid_app ADD COLUMN client_secret_hash  VARCHAR(255);
ALTER TABLE mxid_app ADD COLUMN logo_url            VARCHAR(500);
ALTER TABLE mxid_app ADD COLUMN home_url            VARCHAR(500);
ALTER TABLE mxid_app ADD COLUMN is_first_party      BOOLEAN      NOT NULL DEFAULT TRUE;
ALTER TABLE mxid_app ADD COLUMN require_consent     BOOLEAN      NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX idx_app_client_id ON mxid_app(client_id);
CREATE INDEX idx_app_tenant_protocol ON mxid_app(tenant_id, protocol, status);
```

DB CHECK constraints:
- `client_type IN ('web_app','spa','native','m2m')`
- `client_type IN ('spa','native') AND client_secret_hash IS NULL` OR `client_type IN ('web_app','m2m') AND client_secret_hash IS NOT NULL`

### 7.3 `protocol_config` JSONB Schema for OIDC

```json
{
  "redirect_uris": ["https://example.com/callback"],
  "post_logout_redirect_uris": ["https://example.com/"],
  "allowed_origins": ["https://example.com"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scopes": ["openid", "profile", "email"],
  "token_endpoint_auth_method": "client_secret_basic",
  "pkce_required": true,
  "require_consent": false,
  "access_token_lifetime": 3600,
  "id_token_lifetime": 3600,
  "refresh_token_lifetime": 2592000,
  "refresh_token_rotation": false,
  "id_token_signing_alg": "RS256",
  "subject_type": "public"
}
```

### 7.4 client_id / client_secret Generation

- `client_id = "client_" + base62(22 chars)` (Auth0-style readable prefix)
- `client_secret = base64url(48 random bytes)` ≈ 64 chars
- Hash with bcrypt cost=12, store `client_secret_hash`
- Plaintext returned exactly once on create / rotate

### 7.5 Redirect URI Validation

- Exact string match (scheme, host, port, path, query — case sensitive)
- No wildcards in A; localhost port wildcards permitted in B
- HTTPS required in production; `http://localhost` and `http://127.0.0.1` permitted by spec for development
- Cap at 100 URIs per app
- Validation enforced in service layer + database CHECK if feasible

### 7.6 PKCE Policy

- `spa` / `native`: required, S256 only
- `web_app`: optional, S256 only (`plain` rejected)
- `m2m`: not applicable
- Discovery removes `plain` from `code_challenge_methods_supported`

### 7.7 Client Auth Methods by Milestone

| Method | A | B | C |
|---|---|---|---|
| `client_secret_basic` | ✓ | ✓ | ✓ |
| `client_secret_post` | ✓ | ✓ | ✓ |
| `none` (PKCE only) | ✓ | ✓ | ✓ |
| `client_secret_jwt` | – | ✓ | ✓ |
| `private_key_jwt` | – | ✓ | ✓ |
| `tls_client_auth` | – | – | ✓ |

## 8. Scopes, Claims, Consent

### 8.1 Scopes Implemented in A

`openid` (mandatory), `profile`, `email`, `phone`, `groups`, `offline_access` (triggers refresh token).

B adds: `address`, `roles`, `organization`, custom per-app scopes.

### 8.2 Claims Assembler

A dedicated `internal/domain/user/claims_assembler.go` is responsible for projecting a `User` record + group memberships into a claim map filtered by requested scopes. Default mapping:

| Source | Claim | Scope |
|---|---|---|
| `user.id` | `sub` | `openid` |
| `user.username` | `preferred_username` | `profile` |
| `user.display_name` | `name` | `profile` |
| `user.avatar_url` | `picture` | `profile` |
| `user.locale` | `locale` | `profile` |
| `user.email` | `email` | `email` |
| `user.email_verified` | `email_verified` | `email` |
| `user.phone` | `phone_number` | `phone` |
| `user.phone_verified` | `phone_number_verified` | `phone` |
| `user_group` join | `groups` (array) | `groups` |

### 8.3 Consent

**A milestone**: skipped. Field added to `mxid_app` (`require_consent BOOLEAN DEFAULT FALSE`); `authorize` handler treats it as `false` regardless. Reason: A is a happy-path integration. First-party apps in a single-tenant deployment do not require consent by default — matches Auth0 / Okta first-party app behavior.

**B milestone**: implements consent screen at `/consent?app_id=...&scope=...` with persistence in `mxid_user_app_consent` and revocation UI in portal.

### 8.4 Subject Type

A: `public` only (single global `sub` per user). B: schema readiness for `pairwise`. C: full `pairwise` with sector identifier URI.

## 9. Console UI

### 9.1 Routes

```
/apps                   List
/apps/new               Type picker → form
/apps/:id               Detail (tabs)
  /settings             Basic info + protocol
  /oidc                 OIDC config
  /credentials          Client ID / Secret / Public key
  /quickstart           Code samples
```

### 9.2 Settings Tab

Fields: `name` (required), `description`, `logo_url`, `home_url`, `client_type` (radio), `protocol` (radio; A locks to OIDC), `status` (toggle).

### 9.3 OIDC Tab

Fields: `redirect_uris` (multi-line list editor with per-URI add/remove + format validation), `post_logout_redirect_uris`, `allowed_origins`, `grant_types` (checkboxes), `response_types` (A locked to `code`), `scopes` (`openid` locked, others checkbox), `token_endpoint_auth_method` (select; SPA/Native locked to `none`), `pkce_required` (SPA/Native locked checked), token lifetimes (number inputs in seconds), `refresh_token_rotation` (B), `id_token_signing_alg` (A locked to RS256), `subject_type` (A locked to `public`).

### 9.4 Credentials Tab

- `client_id`: read-only with copy button; `Regenerate` action issues new id (rare, audited)
- `client_secret`: hidden display; `Reveal` only works once immediately after create/rotate, then permanently shows hash placeholder; `Rotate` button generates new secret (one-time reveal)
- Public key PEM display + `.pem` download

### 9.5 Quickstart Tab

Auto-generates copy-paste code samples per `client_type`:
- Web App: Go (`golang.org/x/oauth2` + `coreos/go-oidc`), Node.js (`openid-client`)
- SPA: React (`react-oidc-context` or hand-rolled fetch)
- Native: Swift (`AppAuth-iOS`), Kotlin (`AppAuth-Android`)
- M2M: curl, Go, Python

Templates inject the app's own `client_id`, `client_secret` placeholder, `issuer`, `redirect_uri`.

## 10. Portal UI

### 10.1 Application Library

`/apps` page (already scaffolded) extended to render a grid of cards. Each card: logo, name, protocol badge, "Open" CTA.

Data source: `GET /api/v1/portal/apps` returns apps visible to the current user. A milestone returns all `status=enabled` apps; B adds RBAC filtering.

### 10.2 Click Behavior (A milestone)

OIDC apps: navigate browser to `home_url`. The RP detects an unauthenticated session and redirects to `/protocol/oidc/authorize`, where MXID's `mxid_proto_sid` cookie short-circuits the login prompt and issues a code.

IdP-initiated flow (`GET /protocol/oidc/authorize?client_id=...` without prior RP redirect) is deferred to B; some RPs do not handle IdP-initiated.

## 11. Testing Strategy

### 11.1 Test Layers (A delivery)

| Layer | Tooling | Coverage |
|---|---|---|
| Unit | `go test` + `testify` | handler / service / resolver / token / claims_assembler |
| Integration | docker-compose `postgres` + `redis`, Go HTTP tests | full authorize → token → userinfo via real HTTP |
| Sample RP | `tools/test-rp-curl`, `tools/test-rp-go`, `tools/test-rp-node` | spec conformance & integration docs |
| Seed | `scripts/seed-test-oidc.sh` | creates `oidc-test` app + test user in dev DB |

### 11.2 Test Sample RP Inventory

- `tools/test-rp-curl/run.sh` — 5-step annotated curl script; CI-friendly
- `tools/test-rp-go/main.go` — ~80 LOC HTTP server, runs on `:8090`, demonstrates standard Go OIDC integration
- `tools/test-rp-node/index.js` — Express + `openid-client`, demonstrates standard Node OIDC integration
- Each RP's README lists exact env vars and one-liner to run

### 11.3 Critical Test Cases (A)

- authorize → code → token → userinfo (happy path)
- PKCE S256 success
- PKCE S256 mismatch (rejected)
- `code_challenge_method=plain` rejected
- Invalid `redirect_uri` rejected
- Disabled app rejected
- `prompt=none` without session → `login_required`
- `prompt=none` with session → success
- `prompt=login` with session → forces re-auth
- Authorization code single-use enforcement
- Expired authorization code rejected
- Refresh token grant success
- Refresh token after expiry rejected
- Invalid client_secret rejected
- id_token signature verifiable via JWKS
- access_token verifiable via JWKS
- Session cookie absence → redirect to login
- Logout from portal preserves `mxid_proto_sid`

### 11.4 Deferred Coverage (B/C)

- Consent flow E2E
- Refresh token rotation reuse detection
- Back-channel logout propagation
- OIDC Conformance Suite (C)
- Playwright multi-browser SSO scenarios (B)

## 12. Data Model Changes

### 12.1 New / Altered Tables (A milestone)

```sql
-- 00X_oidc_app_extensions.up.sql

ALTER TABLE mxid_app
    ADD COLUMN client_id          VARCHAR(64),
    ADD COLUMN client_type        VARCHAR(20)  NOT NULL DEFAULT 'web_app',
    ADD COLUMN client_secret_hash VARCHAR(255),
    ADD COLUMN logo_url           VARCHAR(500),
    ADD COLUMN home_url           VARCHAR(500),
    ADD COLUMN is_first_party     BOOLEAN      NOT NULL DEFAULT TRUE,
    ADD COLUMN require_consent    BOOLEAN      NOT NULL DEFAULT FALSE;

-- backfill existing rows
UPDATE mxid_app SET client_id = 'client_' || substr(md5(id::text || random()::text), 1, 22)
WHERE client_id IS NULL;

ALTER TABLE mxid_app ALTER COLUMN client_id SET NOT NULL;
CREATE UNIQUE INDEX idx_app_client_id ON mxid_app(client_id);
CREATE INDEX idx_app_tenant_protocol ON mxid_app(tenant_id, protocol, status);

ALTER TABLE mxid_app ADD CONSTRAINT chk_client_type
    CHECK (client_type IN ('web_app','spa','native','m2m'));

ALTER TABLE mxid_app ADD CONSTRAINT chk_secret_required
    CHECK (
        (client_type IN ('spa','native') AND client_secret_hash IS NULL)
        OR (client_type IN ('web_app','m2m') AND client_secret_hash IS NOT NULL)
    );
```

### 12.2 New Tables (B milestone)

```sql
-- 00X_user_app_consent.up.sql (B)

CREATE TABLE mxid_user_app_consent (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT NOT NULL,
    user_id     BIGINT NOT NULL,
    app_id      BIGINT NOT NULL,
    scopes      TEXT[] NOT NULL,
    granted_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMP,
    UNIQUE (tenant_id, user_id, app_id)
);
```

### 12.3 Existing `mxid_app_cert` Verification

Confirm columns: `kid`, `algorithm`, `status`, `not_before`, `not_after`, `private_key` (storing encrypted bytes), `public_key`. Add `algorithm VARCHAR(20) NOT NULL DEFAULT 'RS256'` if absent.

## 13. Endpoint Inventory

### 13.1 Protocol Layer (`/protocol/oidc/*`) — A milestone

| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/openid-configuration` | Discovery; aligned to A capabilities |
| GET, POST | `/authorize` | Authorization endpoint; reads `mxid_proto_sid` |
| POST | `/token` | Token endpoint; supports authorization_code, refresh_token, client_credentials |
| GET, POST | `/userinfo` | Returns claims filtered by access token's scope |
| GET | `/jwks` | IdP-level aggregate JWK Set |
| POST | `/revoke` | RFC 7009 token revocation |
| POST | `/introspect` | RFC 7662 token introspection (basic) |
| GET | `/end-session` | RP-initiated logout; deletes `mxid_proto_sid` |

### 13.2 Console API (`/api/v1/console/apps/*`)

| Method | Path | Description |
|---|---|---|
| GET | `/apps` | Paginated list (extends existing) |
| POST | `/apps` | Create app + auto-gen signing key + return one-time `client_secret` |
| GET | `/apps/:id` | Detail with `protocol_config` |
| PUT | `/apps/:id` | Update basic info + `protocol_config` |
| DELETE | `/apps/:id` | Soft delete (`status=deleted`) |
| POST | `/apps/:id/regenerate-secret` | New secret returned once |
| POST | `/apps/:id/rotate-signing-key` | B milestone |
| GET | `/apps/:id/quickstart/:lang` | Returns code snippet |

### 13.3 Portal API (`/api/v1/portal/apps/*`)

| Method | Path | Description |
|---|---|---|
| GET | `/apps` | Apps visible to current user |

### 13.4 Auth API — A milestone modifications

| Method | Path | Change |
|---|---|---|
| POST | `/api/v1/portal/auth/login` | Add `mxid_proto_sid` cookie write + Redis proto session create |
| POST | `/api/v1/console/auth/login` | Same as portal |
| POST | `/api/v1/portal/auth/logout` | Only deletes `mxid_portal_sid` and its Redis key |
| POST | `/api/v1/console/auth/logout` | Only deletes `mxid_console_sid` and its Redis key |

## 14. Security Considerations

| Concern | Mitigation |
|---|---|
| Authorization code injection | Single-use codes, 10-min TTL, bind to client_id + redirect_uri at issue time |
| PKCE downgrade | `plain` not advertised, server rejects `plain` even if requested |
| Open redirect | Strict exact-match `redirect_uri` validation |
| Token theft via XSS | HttpOnly cookies; access_token returned only in token endpoint response (not via cookie) |
| CSRF on authorize endpoint | `state` parameter validation; SameSite=Lax cookie |
| client_secret leakage in DB | bcrypt hash storage; plaintext returned exactly once |
| Signing key compromise | AES-GCM encryption at rest; KMS-backed in B/C |
| Session fixation | New cookie value on every login (no reuse) |
| Replay of id_token | `nonce` parameter mandatory for OIDC flows; included in id_token |
| Brute force on client_secret | Rate limit on `/token` endpoint per client_id (B) |
| RP impersonation | Confidential clients require `client_secret`; public clients require PKCE |

## 15. Open Questions for User Review

1. **Remember Me** — defer to B (decided default) or include in A as a small UX addition? Spec assumes B.
2. **JWKS cache TTL** — 5 minutes proposed; some products use 1 hour. Trade-off: shorter TTL = faster rotation propagation, more JWKS fetches.
3. **Access token lifetime default** — 1 hour proposed (Keycloak default). Auth0 SPA default is 24h. Self-hosted enterprise usage often shortens.
4. **`prompt=none` error redirect** — return error to `redirect_uri` (spec) vs HTML error page. Spec mandates redirect; spec compliance applies.
5. **Sample RP languages** — A delivers curl + Go + Node. Add Python (`authlib`) in A or defer?

These are pre-coding decisions; flag any disagreement before plan is written.

## 16. Acceptance Criteria

### A Milestone
- All A-scope test cases in §11.3 pass in CI
- Each sample RP completes the full flow without errors
- Console can create a new OIDC app and the displayed `client_id` / one-time `client_secret` allow the sample RP to authenticate
- Portal lists the new app and clicking it leads through SSO without re-prompting for credentials when `mxid_proto_sid` is present
- No unencrypted private keys in the database
- Discovery document validates against the OIDC Discovery 1.0 schema
- `goimports` / `gofmt` clean; ESLint clean

### B Milestone
- Auth0-equivalent consent UX
- All A criteria continue to hold
- Refresh token rotation with reuse detection demonstrably blocks replayed tokens
- Back-channel logout reaches all subscribed RPs within 30 seconds

### C Milestone
- OpenID Foundation Conformance Suite passes for OP Basic + OP Implicit + OP Hybrid + OP Logout profiles
- Conformance suite added to CI

## 17. Out of Scope

- SAML, CAS, JWT SSO, FORM Fill protocols (separate specs)
- Social / LDAP identity sources (separate specs)
- MFA / WebAuthn enrollment (separate specs)
- Audit log UI for token events (B will land write path; UI is separate)
- API rate limiting infrastructure (separate spec)
- Multi-tenant key isolation (C)

## 18. References

- OpenID Connect Core 1.0 — https://openid.net/specs/openid-connect-core-1_0.html
- OpenID Connect Discovery 1.0 — https://openid.net/specs/openid-connect-discovery-1_0.html
- OAuth 2.0 — RFC 6749
- PKCE — RFC 7636
- JWT — RFC 7519
- JWS — RFC 7515
- Token Revocation — RFC 7009
- Token Introspection — RFC 7662
- Dynamic Client Registration — RFC 7591 / 7592
- OAuth 2.0 Security Best Current Practice — draft-ietf-oauth-security-topics
- Keycloak OIDC Server — https://www.keycloak.org/docs/latest/server_admin/#sso-protocols
- Auth0 OIDC Conformance — https://auth0.com/docs/get-started/applications/application-grant-types
