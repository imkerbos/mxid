# Compose files

Five files, two environments. Pick by what you are doing — never by guessing.

| File | Used for | How to run |
|---|---|---|
| `docker-compose.dev.yml` | **The dev stack.** Postgres, Redis, Go backend (air hot reload), console + portal vite, nginx on :3500. Self-contained — everything dev needs is in here. | `make dev-up` |
| `docker-compose.dev-ee.yml` | **Overlay, not a separate stack.** Layers on top of `dev.yml` and swaps only the backend to the Enterprise entrypoint (`mxid-ee/cmd/server`). Needs `../mxid-ee` checked out. | `make dev-up EE=1` |
| `docker-compose.yml` | **Prod base.** Released GHCR images, external database (`host.docker.internal` or a real host). | `make prod-up` |
| `docker-compose.ee.yml` | Prod overlay — same idea as the dev-ee overlay, swaps the image to the EE build. | `COMPOSE_FILE=...:docker-compose.ee.yml` |
| `docker-compose.standalone.yml` | Prod overlay that **bundles** Postgres + Redis in containers instead of using an external database. For single-box installs. | `make standalone-up` |

Dev and prod use different compose **project names** (`mxid-dev` vs `mxid-prod`),
so they can coexist on one host and their volumes never collide.

## Volumes

Dev data lives in the `mxid-dev` project:

| Volume | Holds | Survives `dev-down`? |
|---|---|---|
| `mxid-dev_pgdata` | The dev database — users, apps, audit | Yes |
| `mxid-dev_redisdata` | Sessions, tickets, rate-limit counters | Yes |
| `mxid-dev_mxid-go-cache`, `…-go-build`, `…-pnpm-store` | Build caches | Yes (cheap to rebuild) |

**Only `make dev-nuke` deletes data**, and it prompts for confirmation. Take a
dump first with `make dev-dump` (writes to `backups/`).

> Never start dev Postgres or Redis with a bare `docker run`. A container
> outside compose isn't managed by `make dev-*`, doesn't show in `make dev-ps`,
> and its volume belongs to no project — which is exactly how a dev database
> ends up sitting in a volume named after prod, one `docker volume prune` away
> from deletion.

## Ports

| Port | Service |
|---|---|
| 3500 | nginx — the only entrypoint you need (portal `/`, console `/admin/`, API `/api/`) |
| 10050 | backend, exposed directly for `curl` debugging |
| 5432 / 6379 | Postgres / Redis, published so host tools (psql, DBeaver, redis-cli) work |

## Config

Dev reads `.env` at the repo root (copy from `.env.example`). Prod reads
`deploy/compose/.env.prod` (copy from `.env.prod.example`), where `COMPOSE_FILE`
selects which overlays apply.
