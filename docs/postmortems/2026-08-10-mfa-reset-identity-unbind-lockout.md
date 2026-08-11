# Postmortem: an MFA reset became a permanent Lark lockout

- Date found: 2026-08-10 (during a routine admin task: resetting one user's MFA)
- Severity: Critical — a real user permanently lost their only means of signing in, and the
  system had no functional path to recreate it
- Origin: a UI-layer response-envelope mismatch present since the `{code,message,data,traceId}`
  envelope convention was adopted, compounded by a soft-delete/`CASCADE` semantics gap and a
  missing recovery API
- Fixed: branch `feat/identity-rebind-204-envelope`, design doc
  `docs/2026-08-10-identity-rebind-and-204-envelope-design.md` (now archived), 16 implementation
  tasks

## Summary

An administrator set out to reset one user's MFA and, over the course of two misclicks, an
external-IdP auto-provisioning collision, and a routine cleanup, permanently locked the user out.
No API anywhere in the system could recreate an identity binding — they were only ever created
by a first-time external login — so the account was unrecoverable through any functional path.

The proximate trigger was a purely cosmetic bug: five endpoints answered a successful delete with
HTTP `204 No Content`, and the frontend's success interceptor read a field off the empty body,
got `undefined`, and reported success as failure. The administrator believed two operations that
had actually succeeded had silently done nothing, and every decision after that was made on false
information. The 204 bug did not, by itself, lock anyone out. What turned a false "删除失败"
toast into a permanent lockout was two structural gaps sitting behind it — a cascade that
`UPDATE` cannot fire, and a one-way door on identity bindings — that had been there long before
this incident and were only exposed by it.

## Timeline

1. **Wrong tab, silent success reported as failure.** The administrator clicked "解绑" (unbind) on
   the user's **identity bindings** tab, intending to reset MFA — the wrong tab. The backend
   unbound the user's Lark identity successfully and answered `204`. The SPA's success
   interceptor read `data.code` off the empty response body, got `undefined` (not `0`), and
   raised it as an API error. The toast read "删除失败" (delete failed). The administrator
   believed nothing had happened, and moved to the actual MFA tab.

2. **Second false failure, and the fallout compounds.** The administrator force-removed the MFA
   factor. Step-up passed, the backend deleted the factor, and it too answered `204` — same bug,
   same false "删除失败" toast. The failure branch in the console's fetch logic skips the list
   reload, so the factor still appeared present in that admin's own session. A second
   administrator, in a separate session, loaded the same page and saw the true state: no MFA
   factor, no Lark binding. Nobody connected the two false toasts to two real successes.

3. **Auto-provisioning collides with the still-live original account.** The user next signed in
   through Lark. With no binding on record, the login fell through to auto-provisioning, which
   found the username already held by the user's own still-live account and minted a new shell
   account with a suffixed username (e.g. `Layne-1`) to avoid the collision. That shell account,
   not the original, ended up holding the user's real Lark `external_id`.

4. **A routine cleanup orphans the binding.** The administrator, treating the unfamiliar shell
   account as junk, deleted it. User deletion in MXID is a **soft** delete (an `UPDATE` that sets
   `deleted_at`). The foreign key from `mxid_user_identity` to `mxid_user` is declared
   `ON DELETE CASCADE` — but **`UPDATE` never fires `CASCADE`**; only a real `DELETE` on the
   parent row does. The identity binding survived the soft-deleted user, now pointing at a row
   nobody could load.

5. **The orphan is found and the login gives up.** The user tried Lark again. The lookup matched
   the orphaned binding, then tried to load its owning user; that lookup is scoped to live rows by
   default, so it came back not-found. The login code wrapped that into a generic error and
   stopped — no fallback to auto-provisioning (the binding *did* exist, so that branch never ran),
   no message explaining anything to the user, no signal reaching an administrator.

Result: permanent lockout. The account existed, the Lark identity existed, and the two could not
be reconnected through any endpoint the system exposed.

## Root causes

### A. The 204 envelope mismatch

Every MXID API answers a request with `{code, message, data, traceId}`, and the SPA's success
interceptor reads `data.code` — a successful write means `code === 0`. `204 No Content` has no
body by definition. An empty body is not an empty envelope; it is the *absence* of one. Reading
`.code` off it produces `undefined`, which the interceptor correctly treats as "not `0`" and
therefore rejects. Five handlers did this: unbind identity, force-remove an MFA factor, revoke
all sessions, revoke one session, and delete an access-eligibility policy. Four returned
`c.JSON(http.StatusNoContent, nil)` directly; the fifth went through a `response.NoContent`
helper built for exactly this purpose. **One of the five had a test asserting the `204`** —
fossilizing the broken contract as the expected behavior instead of catching it.

This is a UI-layer bug in the strict sense — nothing server-side was wrong, the data was
correctly deleted every time — but it was the first domino. Every subsequent misjudgment in the
incident traces back to an administrator trusting a false "failed" report over the system's
actual state.

### B. Soft delete versus `ON DELETE CASCADE`

`ON DELETE CASCADE` is a real-delete mechanism at the database level: it fires when a `DELETE`
statement removes the parent row, because that is the only event Postgres's foreign-key trigger
machinery observes. A soft delete is an `UPDATE` — the row never leaves the table — so the
trigger never fires, and any child row referencing it is silently left behind pointing at a row
that every *application-level* query (which filters on `deleted_at`) will refuse to return. The
schema's cascade guarantee and the soft-delete convention were both applied independently and
correctly in isolation; the incompatibility between them was never handled. The database cannot
cascade on an `UPDATE` — sweeping related rows has to happen in the application layer, explicitly,
wherever the parent is soft-deleted.

### C. A one-way door

The system could destroy an identity binding — through an administrator's unbind, or as a side
effect of deleting the user that held it — but had no path to create one outside of a first-time
external login. Once a binding was gone (deliberately or by orphaning), the *only* way back was
for auto-provisioning to run again, and auto-provisioning does not reattach an existing user's
history — it mints a new one. There was no admin action, no self-service action, and no API call
of any kind that could re-establish a specific `(user, external_id)` pairing once it existed and
then didn't.

## Fix

Four phases, applied on `feat/identity-rebind-204-envelope`:

1. **Envelope fix + guard.** All five handlers now answer `response.OK(c, nil)` (HTTP `200` with
   the standard envelope) instead of `204`. `pkg/response`'s `NoContent` helper — which existed
   only to produce this exact defect — was deleted. A new source-scanning test,
   `internal/httpguard/no_204_test.go`, walks every non-test file under `internal/` and fails the
   build if `http.StatusNoContent` or `response.NoContent(` appears anywhere outside an explicit
   allow-list (CORS preflight is the one legitimate protocol-level empty response). The shared
   frontend API client was also hardened defensively: its success interceptor now treats a `204`,
   a `205`, or a body that didn't parse to an envelope as a pass-through success rather than a
   failure, so a *future* accidental 204 from anywhere fails safe instead of repeating this
   incident.

2. **Soft-deletable identity bindings.** `mxid_user_identity` gained a `deleted_at` column
   (migration `000068`); its uniqueness constraint on `(tenant_id, provider_type, external_id)`
   was converted to a partial unique index that ignores soft-deleted rows, so a re-bind after an
   unbind no longer collides with the tombstoned row. The console gained a "restore" action on a
   user's unbound identities, gated the same way a delete would be (`user.identity.manage`,
   step-up, audited).

3. **Sweep-on-delete, explicit refusal, and user restore.** `Service.Delete` for a user now
   soft-deletes that user's identity bindings *before* soft-deleting the user — closing the
   orphan path from root cause B for future deletions (existing orphans still needed the
   application-layer sweep this phase performs). The external-login resolver now distinguishes
   two cases that used to collapse into the same dead end: a binding pointing at a genuinely
   deleted user answers with a clear "account deleted, contact an administrator" and refuses to
   auto-provision a replacement; a binding that was merely unbound while the user stayed live
   answers "no account linked" — and critically, neither case is allowed to fall through to
   silent auto-provisioning, because both an unbind and a delete are administrator intent that a
   login must not be able to silently overturn. Administrators also gained the ability to restore
   a soft-deleted user account itself, independent of restoring its bindings.

4. **Self-service re-binding through the IdP (EE).** A signed-in user can now re-establish their
   own external-identity binding by re-authenticating against the provider from the portal's
   account-security page, gated on a fresh step-up challenge. Completing the provider's own
   authentication is what proves the user controls that external identity — this is what actually
   closes root cause C. The design explicitly rejected the alternative of letting an administrator
   type an `external_id` by hand: anyone holding `user.identity.manage` could then graft a
   colleague's external account onto an account they control, and audit only tells you about it
   after the fact. The binding logic (a CE hook, `registry.BindIdentityFunc`) implements the same
   three-way occupancy rule as ordinary login: unclaimed → bind; held by a live user → reject;
   held by a *deleted* user → take over, because the caller has just proven possession via OAuth
   and the prior owner is gone. See `docs/ARCHITECTURE.md`'s "Named cross-module seams" for why
   this decision lives in CE's open code and not in the obfuscated EE binary.

## The repair process made comparable mistakes

A postmortem that only blames the original code is less useful than one that admits the fix
process repeated the same shape of error. Four separate times during implementation, something
was believed to guard against regression and did not:

1. **The new frontend regression test was never wired into CI.** `pnpm -r test` appeared in no
   GitHub Actions workflow — the web CI job ran `pnpm -r build` only. A test written specifically
   to prevent this class of bug from recurring would never have executed. (Fixed in the same
   task that added the test; CI now runs `pnpm -r --if-present test`.)
2. **A delete-ordering test asserted only the end state.** The fix for root cause B depends on
   *ordering* — bindings must be swept before the user row is soft-deleted, or the sweep query
   (which excludes bindings on already-deleted users, to avoid re-touching them) would sweep
   nothing. The first test written for this only checked that both the user and its bindings ended
   up soft-deleted, which is true under either ordering. Reversing the two statements would not
   have failed it. A second test using failure injection — forcing the user-delete step to fail
   and asserting the bindings had *already* been swept beforehand — was added and confirmed to
   fail under a deliberately reversed ordering before being confirmed to pass against the real
   code.
3. **A restore test named for a property it never checked.** A test named
   `TestRestoreUserBringsBackTheAccountButNotItsBindings` never created a binding in its setup and
   never asserted anything about binding state afterward. The "but not its bindings" half of the
   name was pure documentation, unverified by the test body. The behavior itself was correct
   (confirmed by reading `RestoreUser`, which never touches `UserIdentity`), but the test would
   have passed against a version of the code that got it wrong. Fixed by seeding a binding and
   asserting it stays unbound, then proving the assertion non-vacuous with a temporary mutation
   that made the test fail as expected before reverting it.
4. **`exhaustruct` does not cover `registry.InitContext`.** The plan cited `exhaustruct` — the
   linter that fails the build on an incompletely-initialized struct literal — as the safety net
   ensuring a new wiring field on `InitContext` couldn't be silently forgotten at the single
   construction site in `app/run.go`. It does not: `.golangci.yml`'s exhaustruct include list only
   matches types under `github.com/imkerbos/mxid/app.`, and `registry.InitContext` lives in
   `pkg/ee/registry`. A future field added to `InitContext` without a matching update to
   `app/run.go` would compile and pass lint silently. This is a pre-existing tooling gap, not
   introduced by this branch, and it is not closed by this branch either — it is recorded here so
   it doesn't get rediscovered from scratch.

**This is the same shape as the incident itself.** Five `204` sites sat in production code with
every light green — build passing, lint passing, one of them backed by a test that had learned to
expect the bug. A guard that asserts an outcome both the correct and the broken code produce is
not a guard; it is a test that merely runs.

Two further findings from the repair, less about testing discipline and more about the specific
defects the diagnosis needed to be honest about:

- **A planned fix was voided as already-done — and the plan's own author had the corresponding
  research gap.** The design doc's root-cause analysis asserted `UNIQUE(tenant_id, username)`
  lacked a `deleted_at` predicate, which would have let a soft-deleted account's username keep
  blocking auto-provisioning of a replacement. That was true of the original migration
  (`000002`), but migration `000047_user_username_soft_delete_unique` had already replaced that
  constraint with a partial unique index five weeks before this incident — and that migration's
  own comment describes the identical failure chain being fixed proactively at the time. The
  design doc's author had read the original 1-file definition without checking whether 67 later
  migrations had touched it. The planned migration `000069` was struck before implementation; the
  correction is recorded in the design doc itself rather than silently dropped.
- **Raw error text leaked into redirect URLs.** The self-service bind flow's callback handler put
  a bind failure's raw `err.Error()` straight into a redirect's query string in three of six
  redirect sites in the same file — reaching the browser's address bar, its history, and access
  logs, including, on database-failure paths, literal fragments of internal error strings (e.g.
  `create identity: %w`-wrapped driver errors). The other three sites in the same file already
  used a fixed, URL-safe slug. Fixed by routing every conflict outcome through the same three
  stable sentinel errors (`registry.ErrExternalIDTaken`, `ErrIdentityAlreadyBound`,
  `ErrExternalUserDeleted`) that cross the CE/EE seam, translated to a slug on the EE side via an
  exhaustive switch with no branch derived from `err.Error()`.
- **A UI that hides itself on failure tells the same lie as the incident.** The portal's
  account-security identity section swallowed fetch errors into an empty array and then rendered
  nothing — making a backend outage indistinguishable from "this tenant has no external IdP
  configured." Its two sibling sections in the same file already surfaced an inline error instead.
  This is the same class of defect as the incident's own "删除失败": the UI asserting something
  the backend never actually said. Fixed to match its siblings.

## Prevention

- `internal/httpguard/no_204_test.go` fails the build if any handler under `internal/` answers
  `204` outside the CORS allow-list. See `docs/ARCHITECTURE.md`, "Invariants enforced by tests."
- The shared frontend API client's success interceptor no longer treats an empty/non-JSON body as
  an envelope failure, so a future accidental `204` fails safe.
- CI now actually runs the frontend test suite (`pnpm -r --if-present test`) instead of build
  only.
- Deleting a user now sweeps its identity bindings first, and both users and identity bindings are
  independently restorable by an administrator — closing the one-way door for the destroy side.
- A signed-in user can re-establish their own binding through the IdP's own authentication —
  closing the one-way door for the create side, without opening the hand-typed-`external_id`
  privilege-escalation vector that was evaluated and rejected.
- General lesson for future guards on this codebase: a test that only pins the end state of a
  process pins nothing about *how* that state was reached. If a fix depends on ordering, causality,
  or "and nothing else changed," write the test to fail when that specific property is violated —
  not just when the final row counts are wrong — and prove it fails against a deliberately broken
  version before trusting it.

## Open items

Two items are unresolved and await a decision or action from a human, not from further
implementation:

- **The console click-through was never performed.** The unbind → "已解绑" (unbound) list →
  restore → back-to-live-list flow, and the equivalent for a soft-deleted MFA-adjacent identity
  section, were verified by build/lint/test and code review only. The implementers had no console
  administrator credentials on the shared dev database and correctly declined to reset one
  unasked. Someone with access needs to click through the real UI before this ships.
- **It is unconfirmed whether the environment where this incident actually occurred sits at
  migration version ≥ 47.** Root cause B (the orphaned binding) is confirmed and environment-
  independent. But the design doc's now-corrected claim about the username constraint was true of
  any environment still on migration `000002`'s original `UNIQUE(tenant_id, username)` — i.e. any
  environment that never received `000047`. If a production instance is on a version below 47, the
  username-collision half of the original failure analysis is real *on that instance*, independent
  of this incident, and worth checking before assuming every deployment is equally protected.
