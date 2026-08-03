#!/usr/bin/env bash
# offline-bundle.sh — build ONE file you can carry into an air-gapped site.
#
# Run this on a machine that CAN reach ghcr.io (your laptop / a CI runner).
# It produces mxid-offline-<version>.tar.gz containing every image, the packaged
# Helm chart, a values template and checksums. Nothing else is needed on the far
# side except this file and scripts/offline-install.sh (which is inside it).
#
#   ./scripts/offline-bundle.sh v1.8.0            # EE (default)
#   ./scripts/offline-bundle.sh v1.8.0 --ce       # CE
#   ./scripts/offline-bundle.sh v1.8.0 --registry ghcr.io/matrixplusio
#
# Requires: docker (with access to the images), helm, tar, sha256sum/shasum.
# For the private EE image: docker login ghcr.io first.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="$REPO_ROOT/deploy/helm/mxid"

VERSION=""
EDITION="ee"
SRC_REGISTRY="ghcr.io/imkerbos"
# The init container that gates backend startup on Postgres/Redis being up.
# An air-gapped cluster can't pull this either — forgetting it is the classic
# way an offline install dies at "Init:ImagePullBackOff".
DEPS_IMAGE="busybox:1.37"

die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --ce) EDITION=ce; shift ;;
    --ee) EDITION=ee; shift ;;
    --registry) SRC_REGISTRY="${2:?--registry needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    v*) VERSION="$1"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ -n "$VERSION" ] || die "usage: $0 vX.Y.Z [--ce|--ee] [--registry <host/ns>]"
command -v docker >/dev/null || die "docker not found"
command -v helm   >/dev/null || die "helm not found"

if command -v sha256sum >/dev/null; then SHA=sha256sum; else SHA="shasum -a 256"; fi

BACKEND_REPO=$([ "$EDITION" = ee ] && echo mxid-ee || echo mxid)
BACKEND_IMAGE="$SRC_REGISTRY/$BACKEND_REPO:$VERSION"
WEB_IMAGE="$SRC_REGISTRY/mxid-web:$VERSION"

# The tarball carries the version (you need to know which one you're holding,
# and rollback means keeping more than one). The directory inside does NOT:
# a stable path makes every upgrade the same two commands and keeps runbooks
# and scripts from hardcoding a version. Extracting a newer bundle over the
# old directory is the intended flow — install.sh reads manifest.env to pick
# the chart, so a leftover file from a previous version is never used.
BUNDLE_DIR="mxid-offline"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/$BUNDLE_DIR"
OUT="$REPO_ROOT/mxid-offline-$EDITION-$VERSION.tar.gz"

log "bundling MXID $EDITION $VERSION from $SRC_REGISTRY"
mkdir -p "$STAGE/images" "$STAGE/chart"

# linux/amd64 throughout: the EE backend is amd64-only (garble under QEMU arm64
# is impractically slow), so pinning the platform keeps every image consistent
# and stops an arm64 laptop from bundling images the cluster can't run.
for img in "$BACKEND_IMAGE" "$WEB_IMAGE" "$DEPS_IMAGE"; do
  log "pull $img"
  docker pull --platform linux/amd64 -q "$img" >/dev/null \
    || die "cannot pull $img — for the private EE image run: docker login ghcr.io"
done

log "saving images (this is the slow part)"
docker save "$BACKEND_IMAGE" "$WEB_IMAGE" "$DEPS_IMAGE" | gzip -1 > "$STAGE/images/images.tar.gz"

log "packaging chart"
helm package "$CHART_DIR" --destination "$STAGE/chart" >/dev/null
CHART_TGZ="$(cd "$STAGE/chart" && ls ./*.tgz | head -1)"

cp "$REPO_ROOT/scripts/offline-install.sh" "$STAGE/install.sh"
chmod +x "$STAGE/install.sh"

# Machine-readable manifest — install.sh reads these instead of re-deriving them.
cat > "$STAGE/manifest.env" <<EOF
MXID_VERSION=$VERSION
MXID_EDITION=$EDITION
MXID_BACKEND_IMAGE=$BACKEND_IMAGE
MXID_WEB_IMAGE=$WEB_IMAGE
MXID_DEPS_IMAGE=$DEPS_IMAGE
MXID_SRC_REGISTRY=$SRC_REGISTRY
MXID_CHART=${CHART_TGZ#./}
EOF

cat > "$STAGE/values.example.yaml" <<EOF
# Minimal air-gapped values for MXID $VERSION ($EDITION).
# Point image.registry at the registry your CLUSTER can reach — install.sh
# retags and pushes the bundled images under exactly this prefix.
edition: $EDITION
image:
  registry: "REPLACE.internal.registry/mxid"
  tag: "$VERSION"

# The init container must also come from the internal registry.
backend:
  waitForDeps:
    image: "REPLACE.internal.registry/mxid/busybox:1.37"

# Canonical external URLs — REQUIRED in production. Release mode refuses to boot
# on a localhost issuer, and getting these wrong makes the IdP mint tokens under
# a placeholder origin.
config:
  issuerUrl: "https://sso.example.com"
  portalUrl: "https://sso.example.com"
  consoleUrl: "https://sso.example.com/admin"
  # Set when a TLS-terminating gateway forwards plaintext HTTP to the pods,
  # otherwise the OIDC engine 403s.
  trustedProxies: "10.0.0.0/8"

# External datastores (managed PostgreSQL / Redis — the chart does not run them).
database:
  host: "postgres.internal"
  port: "5432"
  name: "mxid"
  user: "mxid"
redis:
  host: "redis.internal"
  port: "6379"

# ALL of these are REQUIRED — the chart refuses to render without them and the
# backend rejects dev placeholders in release mode. auditAnchorKey included:
# audit.anchorSink.enabled defaults to TRUE, so it is required unless you
# explicitly set audit.anchorSink.enabled=false.
#
# Generate each key with:  openssl rand -base64 32
#
# KEEP THEM SAFE AND BACKED UP. Losing cryptoKeyEncryptionKey makes every stored
# secret permanently unrecoverable; losing auditChainKey breaks audit-chain
# verification. On upgrades the chart reuses the existing Secret by default
# (secrets.preserveExisting), so these values only take effect on first install.
#
# Prefer --set-string / sealed-secrets / Vault over writing real values here.
secrets:
  databasePassword: ""
  redisPassword: ""
  cryptoKeyEncryptionKey: ""
  auditChainKey: ""
  auditAnchorKey: ""
EOF

cat > "$STAGE/README.txt" <<EOF
MXID offline bundle — $EDITION $VERSION

Contents
  images/images.tar.gz   backend + web + busybox init (linux/amd64)
  chart/${CHART_TGZ#./}  packaged Helm chart
  values.example.yaml    starting point for your values
  install.sh             loads images, pushes to your registry, runs helm
  manifest.env           image names + versions (read by install.sh)
  SHA256SUMS             integrity check

First install
  1. tar xzf mxid-offline-$EDITION-$VERSION.tar.gz && cd mxid-offline
  2. mkdir -p /opt/mxid && cp values.example.yaml /opt/mxid/values.yaml
     chmod 600 /opt/mxid/values.yaml && edit it
  3. ./install.sh --registry <registry-your-cluster-can-reach> \\
       --values /opt/mxid/values.yaml

Upgrade (any later version)
  1. tar xzf mxid-offline-$EDITION-<new>.tar.gz     # same mxid-offline/ dir
  2. cd mxid-offline && ./install.sh                # no arguments needed

Keep values.yaml OUTSIDE this directory — it is replaced on every upgrade.
Run ./install.sh --help for the no-registry (load-onto-nodes) mode.
EOF

log "writing checksums"
(cd "$STAGE" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 $SHA > SHA256SUMS)

tar czf "$OUT" -C "$WORK" "$BUNDLE_DIR"

log "done: $OUT ($(du -h "$OUT" | cut -f1))"
echo
echo "Carry that one file to the air-gapped site, then:"
echo "  tar xzf $(basename "$OUT") && cd $BUNDLE_DIR && ./install.sh --help"
