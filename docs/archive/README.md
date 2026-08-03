# Archive

Historical design records for features that have since shipped. Kept for the
rationale — why a thing was built the way it was — not as current
documentation.

**These documents are frozen. Do not treat them as accurate.** Where they
disagree with the code or with the live docs, the code wins. Cross-links inside
them may point at plan files that were deleted once the work landed.

Current documentation lives one directory up:

| For | Read |
|---|---|
| System design as built | [ARCHITECTURE.md](../ARCHITECTURE.md) |
| Tamper-proof audit chain + anchor format | [AUDIT-CHAIN-DESIGN.md](../AUDIT-CHAIN-DESIGN.md) |
| CE / EE split and feature gating | [EDITIONS.md](../EDITIONS.md) |
| Install and operate | [DEPLOYMENT.md](../DEPLOYMENT.md) |
| Per-app SSO integration | [integrations/](../integrations/) |
| What changed, per release | [CHANGELOG.md](../../CHANGELOG.md) |

## Contents

| Document | Shipped in | Superseded by |
|---|---|---|
| `2026-05-21-mxid-architecture-design.md` | v0.1.0 — the original whole-product design | `ARCHITECTURE.md` |
| `2026-05-23-oidc-idp-complete-design.md` | v0.1.0 — hand-rolled OIDC engine design | Engine replaced by `zitadel/oidc` v3 in v1.2.0 |
| `FORM-FILL-SSO-DESIGN.md` | v1.5.0 — form-fill (SWA) design; still the only written record of the per-user vs shared credential-mode rationale | `ARCHITECTURE.md` (form-fill seam) |
| `FORM-FILL-SSO-B0-SECURITY-SPEC.md` | v1.5.0 — form-fill threat model and security requirements | — |
| `2026-07-05-tamper-proof-audit-phase1.md` … `phase5-provability.md` | v1.1.0 — the five-phase audit-chain build plan | `AUDIT-CHAIN-DESIGN.md` |
