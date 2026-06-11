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

| Gate              | Tool                          | Catches                                                      |
| ----------------- | ----------------------------- | ------------------------------------------------------------ |
| `verify-mod`      | `go mod tidy` diff            | `// indirect` drift, missing `go.sum` rows                   |
| `verify-vet`      | `go vet` + `nilness`/`shadow` | nil-pointer flow, shadowed err returns                       |
| `verify-build`    | `go build ./...`              | single-file `go build main.go` skew; package-level dead refs |
| `verify-lint`     | `golangci-lint`               | `exhaustruct` on `cmd/server` adapters; staticcheck; errcheck |
| `verify-exports`  | `scripts/verify-exports.mjs`  | `package.json` `exports`/`main`/`bin` paths missing on disk  |
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
- **smoke** — captures the case where everything above passes but the wired
  graph crashes on first request. Logs in as the seeded admin, hits one
  endpoint per console module, fails on any non-2xx.

## Pre-commit hook

A hook is installed by `make install-hooks`. It runs the fast subset
(`verify-mod`, `verify-vet`, `verify-build`, and `verify-exports` if web/
files changed). CI runs the full `make verify` plus `make smoke`.

Bypass for trivial commits with `SKIP_VERIFY=1 git commit ...`. CI does not
honor the bypass.

## Adding a new adapter / wiring struct

If a struct holds dependencies that would nil-panic if zero, add it to the
`exhaustruct.include` list in `.golangci.yml` and write a `new...`
constructor. Do not construct it via struct literal outside the constructor.

## Adding a new console module

Add one probe per new module to `scripts/smoke-test.sh` (`PROBES` array).
The probe should hit a cheap list or info endpoint that exercises auth +
authz middleware.
