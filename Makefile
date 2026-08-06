.PHONY: dev dev-console dev-portal dev-web dev-docker-up dev-docker-up-d dev-docker-down dev-docker-logs dev-docker-ps dev-docker-restart dev-docker-reload dev-docker-watch dev-docker-clean \
       build run test lint migrate-up migrate-down migrate-create clean deps \
       verify verify-mod verify-vet verify-build verify-lint verify-web verify-exports verify-i18n-keys verify-i18n-markers verify-error-extraction verify-pinned-tag smoke install-hooks \
       docker-build prod-up prod-down prod-logs standalone-up standalone-down standalone-logs

# Variables
APP_NAME := mxid
MAIN_PATH := cmd/server/main.go
BUILD_DIR := bin
CONFIG_PATH := configs
MIGRATE_DIR := migrations
DB_DSN ?= "postgres://postgres:12345@host.docker.internal:5432/mxid?sslmode=disable"

# Build identity (stamped into the binary / image). VERSION falls back to the
# git tag (v1.2.3) or short sha; CI passes an explicit tag.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE := ghcr.io/imkerbos/$(APP_NAME)

# Development — Go backend (air hot reload)
dev:
	air -c .air.toml

# Development — Frontend
dev-console:
	cd web && pnpm dev:console

dev-portal:
	cd web && pnpm dev:portal

dev-web:
	cd web && pnpm dev

# ── Dev stack ────────────────────────────────────────────────────────────────
# ONE stack (compose project mxid-dev): postgres + redis + backend (air hot
# reload) + console/portal vite + nginx on :3500. Postgres/Redis live in the
# project's own mxid-dev_pgdata / mxid-dev_redisdata volumes — never start them
# outside compose, or the data ends up in a volume nothing owns.
#
#   make dev-up            # start (detached)
#   make dev-up EE=1       # start with the Enterprise backend entrypoint
#   make dev-down          # stop, KEEPING data
#   make dev-logs          # tail the backend
#   make dev-ps            # what's running
#   make seed-demo         # (re)seed demo org/groups/policies
#
# EE=1 layers docker-compose.dev-ee.yml on top: the backend is built from
# mxid-ee/cmd/server (external-IdP / Lark, SCIM, …) instead of CE cmd/server.
# Requires the private mxid-ee repo checked out as a sibling (../mxid-ee).
# Everything else — db, nginx, vite, ports — is inherited.
DEV_COMPOSE := docker compose --env-file .env -f deploy/compose/docker-compose.dev.yml
ifeq ($(EE),1)
DEV_COMPOSE += -f deploy/compose/docker-compose.dev-ee.yml
endif

.PHONY: dev-up dev-down dev-logs dev-ps dev-restart dev-nuke

dev-up:
	$(DEV_COMPOSE) up -d

dev-down:
	$(DEV_COMPOSE) down

dev-logs:
	$(DEV_COMPOSE) logs -f $(if $(S),$(S),mxid)

dev-ps:
	$(DEV_COMPOSE) ps

dev-restart:
	$(DEV_COMPOSE) restart $(if $(S),$(S),mxid)

# DESTRUCTIVE: `down -v` removes the mxid-dev_pgdata / mxid-dev_redisdata
# volumes — every user, app and audit record in your dev database. Take a dump
# first (make dev-dump). Deliberately not aliased to anything shorter.
dev-nuke:
	@printf 'This DELETES the dev database (mxid-dev_pgdata + redisdata). Type YES to continue: ' && read ans && [ "$$ans" = YES ]
	$(DEV_COMPOSE) down -v

# Dump the dev database to backups/ (timestamped). Cheap insurance before
# anything schema-shaped.
dev-dump:
	@mkdir -p backups
	@f="backups/mxid-$$(date +%Y%m%d-%H%M%S).dump"; \
	  docker exec mxid-postgres-dev pg_dump -U $${POSTGRES_USER:-postgres} -d $${POSTGRES_DB:-mxid} -Fc > "$$f" && \
	  echo "wrote $$f"

dev-watch:
	./scripts/dev-watch.sh

# ── Mirror images into your own registry ─────────────────────────────────────
# The normal path when the cluster can't reach ghcr.io but one machine can reach
# both it and your registry. Run on that machine, after `docker login` to both.
#
#   make sync-images TAG=v1.8.0 REGISTRY=harbor.internal/mxid
#   make sync-images TAG=v1.8.0 REGISTRY=harbor.internal/mxid EDITION=ce
#
# Then `helm upgrade` as usual — the script prints the exact command.
.PHONY: sync-images build-images
sync-images:
	@[ -n "$(TAG)" ] && [ -n "$(REGISTRY)" ] || { echo "usage: make sync-images TAG=v1.8.0 REGISTRY=harbor.internal/mxid [EDITION=ce]"; exit 1; }
	./scripts/sync-images.sh $(TAG) $(REGISTRY) --$(if $(EDITION),$(EDITION),ee)

# Same destination, built from source instead of pulled from GHCR. Use when the
# released images can't be pulled at all, you carry local patches, or policy
# requires building from reviewed source. Clones missing sources at TAG; the EE
# build needs ../mxid-ee and runs garble (slow, amd64-only).
#
#   make build-images TAG=v1.8.0 REGISTRY=harbor.example.com/sa02
#   make build-images TAG=v1.8.0 REGISTRY=harbor.example.com/sa02 EDITION=ce
build-images:
	@[ -n "$(TAG)" ] && [ -n "$(REGISTRY)" ] || { echo "usage: make build-images TAG=v1.8.0 REGISTRY=harbor.example.com/sa02 [EDITION=ce]"; exit 1; }
	./scripts/build-images.sh $(TAG) $(REGISTRY) --$(if $(EDITION),$(EDITION),ee)

# ── Fully air-gapped release ─────────────────────────────────────────────────
# Only when NO machine can reach both ghcr.io and your registry. Otherwise use
# sync-images above — it is one step instead of bundle/carry/unpack/install.
# Build ONE tarball (images + packaged chart + values template + checksums) to
# carry into a site with no internet. Run on a machine that CAN reach ghcr.io;
# `docker login ghcr.io` first for the private EE image.
#
#   make offline-bundle TAG=v1.8.0            # EE (default)
#   make offline-bundle TAG=v1.8.0 EDITION=ce
#
# Then at the site: tar xzf the bundle and run ./install.sh --help.
.PHONY: offline-bundle
offline-bundle:
	@[ -n "$(TAG)" ] || { echo "usage: make offline-bundle TAG=v1.8.0 [EDITION=ce]"; exit 1; }
	./scripts/offline-bundle.sh $(TAG) --$(if $(EDITION),$(EDITION),ee)

# Seed the demo fixture: org tree, user groups, memberships, app access and app
# roles, so the demo users (alice … nancy) actually see apps in the portal.
# Idempotent — every statement is ON CONFLICT DO NOTHING against a reserved id
# range, so re-running is a no-op and your own test data is never touched.
.PHONY: backup backup-verify
# Back up the dev database, and prove the file restores. A backup nobody has
# restored is a hope, not a backup — `backup-verify` restores into a throwaway
# database and checks the result rather than trusting the file's size.
backup:
	@docker exec -e PGPASSWORD="$${POSTGRES_PASSWORD}" -e PGUSER=$${POSTGRES_USER:-postgres} \
	  -e PGDATABASE=$${POSTGRES_DB:-mxid} -e MXID_BACKUP_DIR=/tmp \
	  -i mxid-postgres-dev bash -s dump < scripts/backup.sh

backup-verify:
	@test -n "$(FILE)" || { echo "usage: make backup-verify FILE=/tmp/mxid-....dump"; exit 2; }
	@docker exec -e PGPASSWORD="$${POSTGRES_PASSWORD}" -e PGUSER=$${POSTGRES_USER:-postgres} \
	  -i mxid-postgres-dev bash -s verify "$(FILE)" < scripts/backup.sh

.PHONY: seed-demo
seed-demo:
	@docker exec -i mxid-postgres-dev psql -v ON_ERROR_STOP=1 \
	  -U $${POSTGRES_USER:-postgres} -d $${POSTGRES_DB:-mxid} < scripts/seed-demo.sql

# Build
build: build-backend

build-backend:
	CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/server

build-frontend:
	cd web && pnpm install && pnpm build

build-all: build-frontend build-backend

# Run
run:
	go run $(MAIN_PATH) -config $(CONFIG_PATH)

# Test
test:
	go test ./... -v -count=1

test-cover:
	go test ./... -v -count=1 -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	golangci-lint run ./...

lint-fix:
	golangci-lint run --fix ./...

# Dependencies
deps:
	go mod tidy
	go mod verify

# Database migrations
migrate-up:
	migrate -path $(MIGRATE_DIR) -database $(DB_DSN) up

migrate-down:
	migrate -path $(MIGRATE_DIR) -database $(DB_DSN) down 1

migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir $(MIGRATE_DIR) -seq $$name

migrate-force:
	@read -p "Enter version: " version; \
	migrate -path $(MIGRATE_DIR) -database $(DB_DSN) force $$version

migrate-version:
	migrate -path $(MIGRATE_DIR) -database $(DB_DSN) version

# Docker — Production build (version stamped via build args). Builds BOTH the
# backend and the web (nginx + baked SPAs) images, mirroring CI. No `latest`
# tag — CI doesn't publish one, so neither do local builds.
docker-build:
	docker build -f deploy/dockerfile/Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE):$(VERSION) .
	docker build -f deploy/dockerfile/Dockerfile.web \
		-t $(IMAGE)-web:$(VERSION) .

# Prod stack — external DB (host.docker.internal). MXID_TAG defaults to the
# local VERSION so `make prod-up` builds + runs without a separate .env tag.
prod-up:
	MXID_TAG=$(VERSION) docker compose -f deploy/compose/docker-compose.yml up -d --build
prod-down:
	docker compose -f deploy/compose/docker-compose.yml down
prod-logs:
	docker compose -f deploy/compose/docker-compose.yml logs -f

# Prod stack — self-contained (containerized Postgres + Redis + volumes).
standalone-up:
	MXID_TAG=$(VERSION) docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.standalone.yml up -d --build
standalone-down:
	docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.standalone.yml down
standalone-logs:
	docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.standalone.yml logs -f

# Prod via docker compose — single entrypoint; everything comes from
# deploy/compose/.env.prod: COMPOSE_FILE picks the mode (external DB vs bundled
# standalone PG/Redis), MXID_TAG pins the released image, plus secrets / origins
# / cert filenames. Copy deploy/compose/.env.prod.example -> .env.prod first.
prod-docker-up:
	docker compose --env-file deploy/compose/.env.prod up -d
prod-docker-down:
	docker compose --env-file deploy/compose/.env.prod down
prod-docker-logs:
	docker compose --env-file deploy/compose/.env.prod logs -f

# Clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Verify — invariant gates. Run before commit / in CI.
# Each sub-target is independently runnable to localize failures.
verify: verify-mod verify-vet verify-build verify-gormtags verify-lint verify-exports verify-i18n-keys verify-i18n-markers verify-error-extraction verify-pinned-tag verify-web
	@echo "✓ verify OK"

# go.mod / go.sum must match the import graph. Catches indirect-vs-direct drift.
verify-mod:
	@echo "==> verify-mod (go mod tidy diff)"
	@cp go.mod go.mod.bak && cp go.sum go.sum.bak
	@go mod tidy
	@if ! diff -q go.mod go.mod.bak >/dev/null || ! diff -q go.sum go.sum.bak >/dev/null; then \
		mv go.mod.bak go.mod; mv go.sum.bak go.sum; \
		echo "✗ go.mod / go.sum out of sync — run 'go mod tidy' and commit"; exit 1; \
	fi
	@rm -f go.mod.bak go.sum.bak

# Catches nil-pointer flow + unreachable code via standard analyzers.
verify-vet:
	@echo "==> verify-vet"
	go vet ./...

# Builds every Go package, not just main.go. Catches single-file build skew.
verify-build:
	@echo "==> verify-build (./...)"
	go build ./...

# gormtaglint — every struct a GORM query scans into must carry explicit
# `gorm:"column:.."` tags on its exported fields. The EE binary is built with
# garble, which renames Go field names; an untagged field then maps to the wrong
# column and silently scans EMPTY (this shipped as the access-policy "(未知)"
# prod bug). This gate makes that class fail at commit time, on the CE build,
# long before an (untested) EE garble build.
verify-gormtags:
	@echo "==> verify-gormtags (garble-safe GORM scan structs)"
	@cd tools/gormtaglint && go build -o "$(CURDIR)/bin/gormtaglint" .
	@./bin/gormtaglint ./app/... ./internal/... ./cmd/...

# golangci-lint — exhaustruct on app/adapters_*, nilness, errcheck, staticcheck.
verify-lint:
	@echo "==> verify-lint"
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed: https://golangci-lint.run/welcome/install/"; exit 1; }
	golangci-lint run ./...

# package.json `exports` map paths must exist on disk.
verify-exports:
	@echo "==> verify-exports"
	node scripts/verify-exports.mjs

# Every literal t('...') key must resolve in BOTH locales. A missing key does not
# throw — i18next renders the key itself, so the screen fills with
# "account.password.forceTitle" instead of text. That shipped: the forced
# password-change screen, the one screen a locked-out administrator has to use,
# rendered every label as a raw key because the namespace is `account.pwd`.
verify-i18n-keys:
	@echo "==> verify-i18n-keys"
	node scripts/verify-i18n-keys.mjs

# Frontend error text must come from extractMessage — it is the one place that
# knows both error shapes, localizes the fixed-sentence codes, and carries the
# traceId. Reading response.data.message by hand loses all three, which is how a
# 500 became "Request failed with status code 500" with nothing to quote.
verify-error-extraction:
	@echo "==> verify-error-extraction"
	node scripts/verify-error-extraction.mjs

# Labels rendered through <Field required> must not carry their own "*" — the
# primitive draws the marker, so a label ending in one renders "Name * *".
verify-i18n-markers:
	@echo "==> verify-i18n-markers"
	node scripts/verify-i18n-markers.mjs

# The example env files are copied verbatim when deploying, so the tag they pin
# has to be one that still exists. Hits the network; kept out of the pre-commit
# hook for that reason.
verify-pinned-tag:
	@echo "==> verify-pinned-tag"
	node scripts/verify-pinned-tag.mjs

# Frontend production build — strict mode catches what vite dev permits.
verify-web:
	@echo "==> verify-web (pnpm -r build)"
	cd web && pnpm install --prefer-offline --frozen-lockfile && pnpm -r build

# Boot compose + curl every console module endpoint as admin.
smoke:
	@echo "==> smoke"
	./scripts/smoke-test.sh

# EE garble smoke — compiles reflection-sensitive paths UNDER GARBLE (the EE
# obfuscator) and asserts they return real values. Catches untagged GORM/JSON
# scan structs that read empty only in the garbled EE binary. The mxid-ee repo
# has no CI, so this is the mandatory local gate before an EE tag/push; its
# pre-push hook calls `make -C ../mxid ee-smoke`.
ee-smoke:
	@echo "==> ee-smoke"
	./scripts/ee-smoke.sh

# Idempotent: link .git/hooks/pre-commit -> scripts/pre-commit.sh
install-hooks:
	@echo "==> install-hooks"
	./scripts/install-hooks.sh
