# Contributing

## Verify gates

Five gates run before code merges. Each catches a distinct class of silent
contract drift that has historically reached `main`. Run all locally with:

```
make verify
```

Run the boot-level smoke separately (needs compose up):

```
make smoke
```

Backup and restore have their own pair, also against a live dev stack. `backup-verify`
restores the file into a throwaway database and checks it rather than trusting its size:

```
make backup                                  # → /tmp/mxid-<timestamp>.dump
make backup-verify FILE=/tmp/mxid-....dump
```

| Gate              | Tool                          | Catches                                                      |
| ----------------- | ----------------------------- | ------------------------------------------------------------ |
| `verify-mod`      | `go mod tidy` diff            | `// indirect` drift, missing `go.sum` rows                   |
| `verify-vet`      | `go vet` + `nilness`/`shadow` | nil-pointer flow, shadowed err returns                       |
| `verify-build`    | `go build ./...`              | single-file `go build main.go` skew; package-level dead refs |
| `verify-lint`     | `golangci-lint`               | `exhaustruct` on the `app/` wiring adapters; staticcheck; errcheck |
| `verify-exports`  | `scripts/verify-exports.mjs`  | `package.json` `exports`/`main`/`bin` paths missing on disk  |
| `verify-i18n-markers` | `scripts/verify-i18n-markers.mjs` | a `<Field required>` label that also ends in `*`, so the marker renders twice |
| `verify-toaster-mount` | `scripts/verify-toaster-mount.mjs` | `<Toaster />` mounted inside a layout (or twice), so screens outside it raise toasts nobody renders |
| `verify-pinned-tag` | `scripts/verify-pinned-tag.mjs` | an example env file pinning an image tag that no longer exists |
| `verify-web`      | `pnpm -r build`               | Vite prod-mode strictness that dev mode tolerates             |
| `smoke`           | `scripts/smoke-test.sh`       | runtime nil-pointer in cross-module wiring; middleware order |

## Why these gates exist

Each gate exists because a real bug shipped past everything else:

- **verify-mod** — `gorm.io/datatypes` lived as `// indirect` while 6 files
  imported it directly. `go build` doesn't auto-promote indirect → direct;
  only `go mod tidy` does. Gate detects the drift on every commit.
- **verify-build** — `.air.toml` used `go build -o tmp/mxid cmd/server/main.go`,
  which compiles a single file and silently drops `adapters_*.go` in the
  same package. Symptom: hours of "undefined: X" panics. Gate is `go build
  ./...` which always builds whole packages.
- **verify-lint** (`exhaustruct`) — `&authzBindingProvider{permModule: …}`
  silently zero-valued `app`. Result: runtime nil-deref on first request.
  `exhaustruct` forces every field at construction; constructors
  (`newAuthzBindingProvider(...)`) make missing args a compile error.
- **verify-exports** — `package.json` had `"./ui": "./src/ui/index.ts"` but
  the file is `.tsx`. Vite dev resolved nothing; broke the whole console.
  Gate walks every `package.json` and asserts the path exists.
- **verify-toaster-mount** — both apps mounted `<Toaster />` inside
  `MainLayout`, and both render screens outside it (the portal's `/step-up`
  page and forced MFA-enrollment gate, the console's login and forced
  password-change gates). `toast.*` is a pub-sub, so those screens published
  into nothing: a failed step-up reported *no* error at all and the button
  looked dead. Gate asserts exactly one mount, in `App.tsx`.
- **verify-pinned-tag** — `.env.example` pinned `MXID_TAG=v0.1.0` long after
  that tag stopped being published. `cp .env.example .env` is step one of the
  compose path, so the first thing a new user saw was ImagePullBackOff on an
  image that does not exist. Kept out of the pre-commit hook: it hits the
  network.
- **verify-i18n-markers** — six labels ended in `*` while also being passed to
  `<Field required>`, which draws its own marker, so forms rendered `Name * *`.
  Nothing about that fails to compile; it was found in a screenshot. The gate
  reads the actual call sites rather than a hand-kept list, so migrating another
  form onto the primitive and forgetting to strip its label fails.
- **smoke** — captures the case where everything above passes but the wired
  graph crashes on first request. Logs in as the seeded admin, hits one
  endpoint per console module, fails on any non-2xx.

## Pre-commit hook

A hook is installed by `make install-hooks`. It runs the fast subset
(`verify-mod`, `verify-vet`, `verify-build`, and `verify-exports` +
`verify-i18n-markers` if web/ files changed). CI runs the full `make verify` plus `make smoke`.

Bypass for trivial commits with `SKIP_VERIFY=1 git commit ...`. CI does not
honor the bypass.

## Adding a new adapter / wiring struct

If a struct holds dependencies that would nil-panic if zero, add it to the
`exhaustruct.include` list in `.golangci.yml` and write a `new...`
constructor. Do not construct it via struct literal outside the constructor.

The include patterns are fully-qualified type names
(`github.com/imkerbos/mxid/app\.<Type>$`). They match nothing — and the linter
silently passes — if the package path is wrong, so verify a new entry actually
fires before trusting it.

## Adding a new console module

Add one probe per new module to `scripts/smoke-test.sh` (`PROBES` array).
The probe should hit a cheap list or info endpoint that exercises auth +
authz middleware.
