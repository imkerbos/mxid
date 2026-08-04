# Build stage — pin the patch version to satisfy go.mod's `go 1.25.12` directive
# (the floating 1.25-alpine tag can lag behind by a patch release).
FROM golang:1.25.12-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build identity stamped into the binary via -ldflags. Passed by CI (release.yml)
# from the git tag / sha / build timestamp; defaults keep local builds at "dev".
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X github.com/imkerbos/mxid/pkg/version.Version=${VERSION} \
      -X github.com/imkerbos/mxid/pkg/version.Commit=${COMMIT} \
      -X github.com/imkerbos/mxid/pkg/version.BuildTime=${BUILD_TIME}" \
    -o /app/bin/mxid ./cmd/server

# Runtime stage
FROM alpine:3.22

# apk upgrade first pulls the latest patched packages (closes any base-image lag
# CVEs), then install the runtime deps.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata wget

# Run as an unprivileged user. uid 1000 matches the securityContext the Helm
# chart already applies, so the two deployment paths agree; the compose path had
# no equivalent and ran the server as root. The binary is static, listens above
# 1024 and writes nothing to disk (logs go to stdout, uploads to the database),
# so it needs no privilege at all.
RUN addgroup -g 1000 -S mxid && adduser -u 1000 -S mxid -G mxid

WORKDIR /app

COPY --from=builder /app/bin/mxid .
# configs baked in as a fallback. Prod mounts configs/ read-only over this so
# config changes don't require an image rebuild (see deploy/compose/*.yml).
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/migrations ./migrations

# Owned by root and readable, not writable, by the runtime user: nothing the
# server does should be able to rewrite its own binary, config or migrations.
RUN chown -R root:root /app && chmod -R a-w /app

USER mxid:mxid

EXPOSE 8080

ENTRYPOINT ["./mxid"]
CMD ["-config", "configs"]
