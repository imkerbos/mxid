# Security Policy

MXID is an identity platform — security reports are taken seriously and triaged ahead of feature work.

## Reporting a vulnerability

**Do not** open a public GitHub issue for security bugs.

Email **0xkerbos@gmail.com** with:

- A description of the vulnerability.
- Steps to reproduce or a proof-of-concept.
- Affected version / commit SHA.
- Your assessment of impact (info disclosure, auth bypass, RCE, …).
- Whether you intend public disclosure and your preferred timeline.

We aim to:

- Acknowledge receipt within **72 hours**.
- Provide an initial assessment within **7 days**.
- Ship a fix or mitigation within **30 days** for high / critical issues.

If you do not hear back within 7 days, please re-send — mail filters do happen.

## Disclosure

We follow **coordinated disclosure**. Once a fix is available we will:

1. Publish the patched version.
2. Credit you in the release notes (unless you ask otherwise).
3. Publish a GitHub Security Advisory with the CVE (when applicable).

We support the latest released minor version with security patches. Older versions get fixes only on a best-effort basis.

## Out of scope

The following are typically **not** treated as vulnerabilities:

- Issues that require physical access to a user's device.
- Self-XSS that requires the user to paste payloads into their own browser console.
- Missing best-practice security headers without a concrete exploit path.
- Reports against demo / dev configurations (`config.dev.yaml`, the Docker compose defaults). Production deployments are expected to set strong secrets and proper TLS.

## Hardening checklist for operators

Beyond reporting bugs, MXID operators should:

- Run behind HTTPS (TLS 1.2+).
- Set strong `MXID_MASTER_KEY` (32 random bytes, base64). This key encrypts SMTP password, SMS secret, etc.
- Set strong `MXID_JWT_PRIVATE_KEY` (RSA 2048+ or ECDSA P-256).
- Set strong `MXID_SESSION_SECRET` for cookie HMAC.
- Restrict admin console access (network ACL or VPN).
- Set `cookie_secure: true` and `cookie_domain` correctly when not on localhost.
- Enable MFA for the `admin` account immediately.
- Configure `AuditPolicy.AlertWebhookURL` to monitor failed logins / privilege changes.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full production checklist.
