#!/usr/bin/env bash
# offline-install.sh — install/upgrade MXID inside an air-gapped site.
#
# Ships INSIDE the bundle produced by scripts/offline-bundle.sh; run it from the
# unpacked bundle directory. It never reaches the internet.
#
#   ./install.sh --registry harbor.internal/mxid --values values.yaml
#   ./install.sh --registry harbor.internal/mxid --values values.yaml --dry-run
#   ./install.sh --load-only            # no registry: just import images locally
#
# Two delivery modes:
#   registry mode (default, recommended) — retag the bundled images under your
#     internal registry and push. Works with any number of nodes and survives
#     scale-out, because the kubelet pulls normally.
#   --load-only — import into the local container runtime only. You must run it
#     on EVERY node, and a node added later will not have the images. Use it
#     only when there is genuinely no registry.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY=""
VALUES=""
RELEASE="mxid"
NAMESPACE="mxid"
LOAD_ONLY=0
DRY_RUN=0
SKIP_VERIFY=0

die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --registry)  REGISTRY="${2:?--registry needs a value}"; shift 2 ;;
    --values)    VALUES="${2:?--values needs a value}"; shift 2 ;;
    --release)   RELEASE="${2:?}"; shift 2 ;;
    --namespace|-n) NAMESPACE="${2:?}"; shift 2 ;;
    --load-only) LOAD_ONLY=1; shift ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    -h|--help)   sed -n '2,22p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -f "$HERE/manifest.env" ] || die "manifest.env not found — run this from inside the unpacked bundle"
# shellcheck disable=SC1091
. "$HERE/manifest.env"

# Pick whichever container tool exists. containerd-only nodes (no docker) are
# common in k8s, so support ctr/nerdctl too.
if command -v docker >/dev/null;  then RUNTIME=docker
elif command -v nerdctl >/dev/null; then RUNTIME=nerdctl
elif command -v ctr >/dev/null;     then RUNTIME=ctr
else die "need docker, nerdctl or ctr to load images"; fi

# ── integrity ────────────────────────────────────────────────────────────────
if [ "$SKIP_VERIFY" -eq 0 ]; then
  log "verifying checksums"
  if command -v sha256sum >/dev/null; then SHA=sha256sum; else SHA="shasum -a 256"; fi
  (cd "$HERE" && $SHA -c SHA256SUMS --quiet) \
    || die "checksum mismatch — the bundle is corrupt or was modified in transit"
fi

# ── load images ──────────────────────────────────────────────────────────────
log "loading images into $RUNTIME (this is the slow part)"
case "$RUNTIME" in
  docker|nerdctl) gunzip -c "$HERE/images/images.tar.gz" | $RUNTIME load ;;
  ctr)            gunzip -c "$HERE/images/images.tar.gz" | ctr -n k8s.io images import - ;;
esac

if [ "$LOAD_ONLY" -eq 1 ]; then
  log "images loaded. --load-only: nothing pushed, helm not run."
  warn "run this on EVERY node, and set image.pullPolicy=IfNotPresent in your values,"
  warn "or the kubelet will still try to pull from a registry it cannot reach."
  echo
  echo "Loaded:"
  echo "  $MXID_BACKEND_IMAGE"
  echo "  $MXID_WEB_IMAGE"
  echo "  $MXID_DEPS_IMAGE"
  exit 0
fi

[ -n "$REGISTRY" ] || die "--registry is required (or use --load-only). Example: --registry harbor.internal/mxid"

# ── preflight ────────────────────────────────────────────────────────────────
# Validate the values file BEFORE pushing three images, so a missing key costs
# seconds instead of a full push cycle.
command -v helm >/dev/null || die "helm not found on this machine"
[ -n "$VALUES" ] || die "--values is required (start from values.example.yaml)"
[ -f "$VALUES" ] || die "values file not found: $VALUES"
grep -q 'REPLACE\.internal\.registry' "$VALUES" \
  && die "$VALUES still contains the REPLACE.internal.registry placeholder — edit it first"

# auditAnchorKey is in the list because audit.anchorSink.enabled defaults to
# true; the chart hard-fails without it unless the sink is explicitly disabled.
for k in databasePassword cryptoKeyEncryptionKey auditChainKey auditAnchorKey; do
  # Matches `  key: ""` / `  key: ''` / `  key:` with nothing after it.
  if grep -Eq "^[[:space:]]*${k}:[[:space:]]*(\"\"|'')?[[:space:]]*$" "$VALUES"; then
    die "secrets.$k is empty in $VALUES — the chart will refuse to render.
       Generate one with: openssl rand -base64 32
       (or pass it at install time with --set-string secrets.$k=...)"
  fi
done

# ── retag + push ─────────────────────────────────────────────────────────────
# Repo names must stay mxid / mxid-ee / mxid-web / busybox under your prefix —
# the chart's image helpers append exactly those names to image.registry.
push_one() {
  local src="$1" name="$2" dst="$REGISTRY/$2"
  log "push $dst"
  if [ "$DRY_RUN" -eq 1 ]; then echo "  (dry-run) $src -> $dst"; return; fi
  case "$RUNTIME" in
    docker|nerdctl) $RUNTIME tag "$src" "$dst" && $RUNTIME push "$dst" ;;
    ctr)  ctr -n k8s.io images tag "$src" "$dst" && ctr -n k8s.io images push "$dst" ;;
  esac
}

BACKEND_NAME="${MXID_BACKEND_IMAGE##*/}"   # mxid-ee:v1.8.0
WEB_NAME="${MXID_WEB_IMAGE##*/}"           # mxid-web:v1.8.0
DEPS_NAME="${MXID_DEPS_IMAGE##*/}"         # busybox:1.37

push_one "$MXID_BACKEND_IMAGE" "$BACKEND_NAME"
push_one "$MXID_WEB_IMAGE"     "$WEB_NAME"
push_one "$MXID_DEPS_IMAGE"    "$DEPS_NAME"

# ── helm ─────────────────────────────────────────────────────────────────────
HELM_ARGS=(
  upgrade --install "$RELEASE" "$HERE/chart/$MXID_CHART"
  --namespace "$NAMESPACE" --create-namespace
  --values "$VALUES"
  --set-string "image.registry=$REGISTRY"
  --set-string "image.tag=$MXID_VERSION"
  --set-string "edition=$MXID_EDITION"
  --set-string "backend.waitForDeps.image=$REGISTRY/$DEPS_NAME"
)
[ "$DRY_RUN" -eq 1 ] && HELM_ARGS+=(--dry-run)

log "helm ${HELM_ARGS[*]}"
helm "${HELM_ARGS[@]}"

[ "$DRY_RUN" -eq 1 ] && exit 0

echo
log "waiting for rollout"
kubectl -n "$NAMESPACE" rollout status "statefulset/$RELEASE-backend" --timeout=5m || \
  warn "backend rollout did not settle — check: kubectl -n $NAMESPACE describe pod -l app.kubernetes.io/name=mxid"
kubectl -n "$NAMESPACE" rollout status "deployment/$RELEASE-web" --timeout=3m || true

echo
log "installed MXID $MXID_EDITION $MXID_VERSION"
echo "Verify:  kubectl -n $NAMESPACE exec statefulset/$RELEASE-backend -- wget -qO- localhost:8080/readyz"
