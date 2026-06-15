# MXID OIDC test relying parties

Run these against a local MXID backend (`make dev-docker-up`) to validate the
full Authorization Code flow end-to-end.

## 1. Provision a test OIDC app

```bash
./scripts/seed-test-oidc.sh
```

The script logs in as the seeded `admin` user (password `admin123`),
creates an OIDC application named `oidc-test`, and prints the
`client_id` / `client_secret`. Save them — the secret is shown once.

## 2. Run a relying party

### Bash + curl

```bash
CLIENT_ID=client_xxx CLIENT_SECRET=yyy ./tools/test-rp-curl/run.sh
```

Walks step-by-step through discovery → JWKS → authorize → token → userinfo →
refresh. Educational and CI-friendly.

### Go

```bash
cd tools/test-rp-go
ISSUER=http://localhost:10050 \
CLIENT_ID=client_xxx \
CLIENT_SECRET=yyy \
REDIRECT_URI=http://localhost:8090/callback \
go run .
```

Then open <http://localhost:8090/> in a browser already signed into the
MXID portal at <http://localhost:3501/>. The RP redirects through
`/protocol/oidc/authorize`, exchanges the code, verifies the `id_token`
via JWKS, and dumps the resulting claim set.
