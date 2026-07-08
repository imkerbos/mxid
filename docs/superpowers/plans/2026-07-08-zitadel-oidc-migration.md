# Zitadel OIDC Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the zitadel/oidc engine (`internal/protocol/oidcop`) the sole OIDC provider at full feature parity with the retiring hand-rolled engine (`internal/protocol/oidc`), then delete the hand-rolled engine.

**Architecture:** Prod already runs the zitadel engine (`MXID_OIDC_ENGINE=zitadel`) and has NO onboarded OIDC clients yet, so there is no backward-compat burden — parity gaps are built freely on the zitadel side. Build the missing capabilities into the oidcop `Storage`/bridge/provider, re-wire offboarding + JIT back-channel logout onto the zitadel engine, then remove the hand-rolled package and its env branch. The hand-rolled engine stays mounted (behind the env branch) as a live reference until parity is verified, and is deleted only in the final workstream.

**Tech Stack:** Go 1.25.11, gin, GORM, Redis, `github.com/zitadel/oidc/v3`, `pkg/safehttp` (SSRF guard), `internal/domain/oidckey` (provider keyset + rotation).

## Global Constraints

- Reply to user in Chinese; code / commit messages / PR descriptions in English.
- Conventional Commits, English subject; NO AI/Claude/Anthropic attribution, no Co-Authored-By trailer.
- Do NOT auto-commit — commit only when the user asks. Frequent granular commits WHILE working are fine on the feature branch; squash at merge.
- Commercial-grade, spec-compliant path only. Benchmark Keycloak / Auth0 / Okta.
- All server-side outbound HTTP goes through `pkg/safehttp` (never a bare http.Client).
- Every console/portal write API records audit (who/ip/when/what/result).
- Work on a feature branch, not `main`/`dev`. Keep the pre-commit hook (verify-mod/vet/build/exports) green.
- The public URL surface `/protocol/oidc/*` MUST stay byte-identical (already preserved by `provider.go:34-39`).
- OIDC issuer (`iss`) = `{issuer_url}/protocol/oidc` (zitadel form, spec-compliant). Do NOT change it.

## Scope Decisions (evaluation outcome — keep vs drop)

| Capability | Decision | Rationale |
|---|---|---|
| Back-channel logout (offboarding + JIT) | BUILD | Security control; currently no-op under zitadel |
| Refresh disabled-account guard | BUILD | Offboarded user's refresh must die |
| Refresh reuse/theft detection + family revoke | BUILD | Commercial-grade token security |
| App access-policy check at authorize (`CheckAppAccess`) | BUILD | Access-denied users must not be admitted |
| `app_roles` claim | BUILD | RP role mapping (Grafana/Jenkins) needs it |
| Subject strategy (pairwise/persistent_id/email/username_suffixed) + `tenant_code` + `preferred_username` override | BUILD | Parity; privacy; product |
| `client_secret_jwt` (HS256) client auth | BUILD | Standard client-auth method |
| `client_credentials` grant | BUILD | M2M is a standard commercial feature |
| SSO login-confirmation one-time-token flow | BUILD (port to bridge) | Existing product feature |
| Per-client token-endpoint rate limit | BUILD | Cheap abuse control |
| Implicit response types (`id_token`, `token id_token`) | DROP | Deprecated by OAuth 2.1 |
| Hybrid response types (`code id_token`…) | DEFER | Build only if a concrete SP needs it; not on the critical path |

## Workstreams (dependency-ordered)

- **WS1 — Session identity (`sid`) threading.** Thread the shared protocol session id (`mxid_proto_sid`) into the oidcop auth request and emit it as the id_token `sid`. Foundation for WS2. *Detailed below.*
- **WS2 — Back-channel logout on zitadel.** Participation index writer + provider-keyset logout_token signer + fan-out; re-wire offboarding (`run.go:1064`) and JIT `CompositeTerminator` (`run.go:1104`). *Detailed below.*
- **WS3 — Refresh-token security.** Disabled-account guard on refresh + reuse/family detection with cascade revoke + reuse audit event.
- **WS4 — Authorize-time app access policy.** Invoke `CheckAppAccess` in the login bridge before consent/issue.
- **WS5 — Claims parity.** `app_roles`, subject strategy, `tenant_code`, `preferred_username` override in `oidcop` claims store.
- **WS6 — Client auth + grants.** `client_secret_jwt` (HS256) + `client_credentials` grant; land the implicit-drop decision.
- **WS7 — SSO login-confirmation flow.** Port `ssoflow.ConfirmStore` handshake into the oidcop bridge.
- **WS8 — Per-client token-endpoint rate limit.** Port `internal/protocol/oidc/ratelimit.go` behavior to the oidcop token path.
- **WS9 — Delete hand-rolled engine.** Remove the env branch + `oidcModule` wiring; delete `internal/protocol/oidc/`; update stale docs.

> WS3–WS9 are scoped here but their bite-sized TDD steps are expanded into follow-up plan iterations (per the writing-plans multi-subsystem guidance) as each is reached, so the plan under active execution stays holdable in context. WS1 and WS2 are fully detailed below and are the immediate execution target.

---

## WS1 — Session identity (`sid`) threading

**Files:**
- Modify: `internal/protocol/oidcop/authrequest.go` (carry session id on the auth request)
- Modify: `internal/protocol/oidcop/bridge.go:97-117` (populate session id when the login/consent completes)
- Modify: `internal/protocol/oidcop/claims.go` (emit `sid` into the id_token)
- Test: `internal/protocol/oidcop/sid_test.go` (new)

**Interfaces:**
- Consumes: the shared protocol session id — the same value the hand-rolled engine reads as the session cookie / `sessionMgr` session id (hand-rolled ref: `handler.go:444` keys `mxid:sso:apps:<sid>` on it; logout iterates `session.Manager.ListByUser(NamespaceProtocol, userID)` → `s.ID`).
- Produces: `authRequest.GetSessionID() string` returning the shared proto session id; id_token carries `sid` == that value.

- [ ] **Step 1: Write the failing test** — `sid_test.go`: construct an oidcop `authRequest` seeded with a known proto session id, run it through the claims path, assert the resulting id_token claims map has `sid` equal to that session id.
- [ ] **Step 2: Run it, verify FAIL** (`go test ./internal/protocol/oidcop/ -run TestIDToken_Sid -v`) — expect fail (no `sid` emitted today).
- [ ] **Step 3: Add a `sessionID` field to the oidcop `authRequest`** (`authrequest.go`) plus a `GetSessionID()` accessor; ensure it is persisted/restored with the rest of the auth request.
- [ ] **Step 4: Populate it in the bridge** where the auth request is created/completed after login (`bridge.go` ~97-117), reading the shared proto session id from the same source the login gateway set (`session.Manager` protocol-namespace session id).
- [ ] **Step 5: Emit `sid` in the claims store** (`claims.go`) whenever `GetSessionID()` is non-empty.
- [ ] **Step 6: Run tests, verify PASS**; run the full `oidcop` package tests to confirm no regression.
- [ ] **Step 7: Commit** — `feat(oidc): thread shared protocol session id into zitadel id_token sid`

---

## WS2 — Back-channel logout on the zitadel engine

**Files:**
- Create: `internal/protocol/oidclogout/service.go` — engine-independent fan-out service (no gin/routing).
- Create: `internal/protocol/oidclogout/signer.go` — `Signer` interface + provider-keyset impl.
- Create: `internal/protocol/oidclogout/participation.go` — `(sid → appIDs)` index reader/writer over Redis (`mxid:sso:apps:<sid>`), destructive `List` + non-destructive `Peek` + `Track`.
- Modify: `internal/protocol/oidcop/bridge.go` — call `participation.Track(sid, appID)` when an auth request completes for a client.
- Modify: `internal/protocol/oidcop/provider.go` — advertise `backchannel_logout_supported`/`_session_supported` in discovery.
- Modify: `app/adapters_oidcop.go` — construct the `oidclogout.Service` (provider-keyset signer + participation index + appResolver + safehttp) and return it from `wireOIDCOP`.
- Modify: `app/run.go:1042-1112` — wire the returned service into `offboarding.LogoutNotifierFunc` and the JIT `CompositeTerminator` for BOTH engines (no more nil/no-op under zitadel).
- Test: `internal/protocol/oidclogout/service_test.go` (port the four scenarios from `internal/protocol/oidc/backchannel_logout_test.go`).

**Interfaces:**
- Consumes: `authRequest.GetSessionID()` (WS1); `session.Manager` (shared); `resolver.AppResolver`; `oidckey.Service` (provider keyset); `pkg/safehttp` client.
- Produces:
  - `oidclogout.Service` with `LogoutUser(ctx, userID int64)` (destructive fan-out, offboarding) and `LogoutUserApp(ctx, userID, appID int64)` (non-destructive peek, JIT).
  - `participation.Index` with `Track(ctx, sid string, appID int64)`, `List(ctx, sid) ([]int64, error)` (destructive), `Peek(ctx, sid) ([]int64, error)`.
  - `Signer` with `SignLogoutToken(claims LogoutTokenClaims) (string, error)`.

- [ ] **Step 1: Write failing test — participation index** (`participation.go` behavior): `Track` two apps on a sid, `Peek` returns both (non-destructive, repeatable), `List` returns both then empties the set. Use miniredis.
- [ ] **Step 2: Run it, verify FAIL** (`go test ./internal/protocol/oidclogout/ -run TestParticipation -v`).
- [ ] **Step 3: Implement `participation.Index`** over Redis key `mxid:sso:apps:<sid>` (mirror `internal/protocol/oidc/store.go:24,35-105` semantics exactly, incl. destructive vs peek).
- [ ] **Step 4: Run, verify PASS.**
- [ ] **Step 5: Write failing test — logout_token signer** using a provider keyset test double: assert the signed JWT has `typ=logout+jwt`, `iss={issuer}/protocol/oidc`, `aud=<clientID>`, `sub=<userID>`, the back-channel-logout `events` marker, and `sid` when session-required.
- [ ] **Step 6: Run, verify FAIL.**
- [ ] **Step 7: Implement `signer.go`** using `oidckey.LoadActiveSigningKey` (RS256, kid from the active key). Claim shape mirrors `internal/protocol/oidc/handler.go:1339-1357`.
- [ ] **Step 8: Run, verify PASS.**
- [ ] **Step 9: Write failing test — fan-out service** porting the four hand-rolled scenarios (`backchannel_logout_test.go`): only-targets-app; no-sessions no-op; JIT peek does not destroy tracking (later full logout still reaches app B); target-app-not-in-session no POST. Inject fake RP httptest servers + a plain http.Client override for loopback.
- [ ] **Step 10: Run, verify FAIL.**
- [ ] **Step 11: Implement `service.go`** — `LogoutUser`/`LogoutUserApp` using `session.Manager.ListByUser(NamespaceProtocol, userID)` + participation index + signer + safehttp POST to each app's `backchannel_logout_uri` (SSRF-guarded; resolve `backchannel_logout_uri`/`backchannel_logout_session_required` via appResolver, mirror `handler.go:1305-1384`).
- [ ] **Step 12: Run, verify PASS.**
- [ ] **Step 13: Wire participation.Track into the oidcop bridge** so each completed auth request records `(sid, appID)`. Add a bridge test asserting Track is called with the WS1 session id.
- [ ] **Step 14: Construct the service in `wireOIDCOP`** and return it; advertise the discovery flags in `provider.go`.
- [ ] **Step 15: Re-wire `run.go`** so `offboardLogout` and `oidcLogout` come from the `oidclogout.Service` regardless of engine (delete the `oidcModule != nil` gating for these two seams). Keep hand-rolled mount intact for now.
- [ ] **Step 16: Run full build + vet + `go test ./...`**, verify green.
- [ ] **Step 17: Commit** — `feat(oidc): back-channel logout on the zitadel engine for offboarding + JIT`

---

## Self-Review notes

- Spec coverage: every audit gap (WS1–WS8) maps to a workstream; the delete mechanics (audit Part 4) are WS9.
- The hand-rolled engine is NOT deleted until WS9, so each earlier workstream can differentially compare against it.
- Verification of the two suspected live security regressions (refresh-guard, app-access) is folded into WS3 and WS4 as their first failing test (the test IS the verification).
