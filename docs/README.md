# MXID documentation

Start at the [project README](../README.md) ([中文](../README_ZH.md)) for what
MXID is and a quickstart.

## Run it

| Document | What it covers |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) · [中文](DEPLOYMENT_ZH.md) | Docker Compose and Helm/Kubernetes install, every env var and chart value, TLS and reverse-proxy setup, health probes, upgrades, backups |
| [EDITIONS.md](EDITIONS.md) | CE vs EE: what each edition includes, how license gating and activation work, what happens on expiry |

## Integrate an application

| Document | What it covers |
|---|---|
| [integrations/README.md](integrations/README.md) | OIDC overview: endpoints, claim mappers, the `X-Forwarded-Proto` trap behind a TLS-terminating proxy |
| [integrations/jenkins-oidc.md](integrations/jenkins-oidc.md) | Jenkins, end to end |

More per-app playbooks (Grafana, JumpServer, Harbor, Gitea, Jira, Confluence,
AWS, Lark, …) ship inside the product: sign in to the console and open
**/admin/docs**. That is the canonical set; this directory holds only the
protocol overview plus the Jenkins guide.

## Understand it

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Package layout, auth and SSO flows, single-logout, the EE seam, HA, error contract |
| [AUDIT-CHAIN-DESIGN.md](AUDIT-CHAIN-DESIGN.md) | Tamper-proof audit: hash chain, Merkle roots, Ed25519 anchors, offline third-party verification |
| [design-system.md](design-system.md) | Frontend tokens, dark mode, shared component kit |
| [ROADMAP-EIAM.md](ROADMAP-EIAM.md) | Capability gaps against commercial EIAM suites, and their current status |

## Project history

| Document | What it covers |
|---|---|
| [CHANGELOG.md](../CHANGELOG.md) | Every release, newest first |
| [postmortems/](postmortems/) | Incident write-ups — institutional memory, kept indefinitely |
| [archive/](archive/) | Design records for shipped features. **Frozen: where they disagree with the code, the code wins.** |

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the dev loop and the local
verification gates, [SECURITY.md](../SECURITY.md) to report a vulnerability, and
[CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md).
