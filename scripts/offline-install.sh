#!/usr/bin/env bash
# offline-install.sh — install/upgrade MXID inside an air-gapped site.
#
# Ships INSIDE the bundle produced by scripts/offline-bundle.sh; run it from the
# unpacked bundle directory. It never reaches the internet.
#
#   First install:
#     ./install.sh --registry harbor.internal/mxid --values /opt/mxid/values.yaml
#   Every upgrade after that — nothing to retype, nothing to re-edit:
#     ./install.sh
#
#   Site settings persist in two places that live OUTSIDE the bundle, so a new
#   bundle never means re-entering them:
#     - your values.yaml (URLs, datastores, secrets) — edited once
#     - a site.conf written on first install (default /etc/mxid/site.conf, or
#       ./site.conf) recording registry / namespace / release / values path
#   If site.conf is missing, settings are read back from the deployed Helm
#   release instead. Explicit flags always win.
#
#   ./install.sh --dry-run              # rehearse; renders locally, no cluster
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
RELEASE=""
NAMESPACE=""
LOAD_ONLY=0
DRY_RUN=0
SKIP_VERIFY=0
CONFIG=""
# Where site settings are remembered between upgrades. Both paths are outside
# the bundle on purpose — the unpacked directory is overwritten by the next
# release, so anything stored in it would be lost exactly when it is needed.
DEFAULT_CONFIGS=("/etc/mxid/site.conf" "$HOME/.config/mxid/site.conf")

die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --registry)  REGISTRY="${2:?--registry needs a value}"; shift 2 ;;
    --values)    VALUES="${2:?--values needs a value}"; shift 2 ;;
    --release)   RELEASE="${2:?}"; shift 2 ;;
    --namespace|-n) NAMESPACE="${2:?}"; shift 2 ;;
    --config)    CONFIG="${2:?--config needs a value}"; shift 2 ;;
    --load-only) LOAD_ONLY=1; shift ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    -h|--help)   sed -n '2,32p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -f "$HERE/manifest.env" ] || die "manifest.env not found — run this from inside the unpacked bundle"
# shellcheck disable=SC1091
. "$HERE/manifest.env"

# ── site settings ────────────────────────────────────────────────────────────
# Precedence: explicit flag > site.conf > the deployed Helm release. The point
# is that a NEW BUNDLE never means re-entering site settings — the bundle is
# disposable, the site config is not, so the config deliberately lives outside
# the unpacked directory.
if [ -z "$CONFIG" ]; then
  for c in "${DEFAULT_CONFIGS[@]}"; do [ -f "$c" ] && { CONFIG="$c"; break; }; done
fi
if [ -n "$CONFIG" ] && [ -f "$CONFIG" ]; then
  log "site config: $CONFIG"
  # shellcheck disable=SC1090
  . "$CONFIG"
  [ -z "$REGISTRY" ]  && REGISTRY="${MXID_SITE_REGISTRY:-}"
  [ -z "$VALUES" ]    && VALUES="${MXID_SITE_VALUES:-}"
  [ -z "$RELEASE" ]   && RELEASE="${MXID_SITE_RELEASE:-}"
  [ -z "$NAMESPACE" ] && NAMESPACE="${MXID_SITE_NAMESPACE:-}"
fi

RELEASE="${RELEASE:-mxid}"
NAMESPACE="${NAMESPACE:-mxid}"

# Last resort: ask the cluster what the previous install used. Lets an upgrade
# work with zero arguments even if site.conf was lost.
if [ "$LOAD_ONLY" -eq 0 ] && [ -z "$REGISTRY" ] && command -v helm >/dev/null; then
  detected="$(helm get values "$RELEASE" -n "$NAMESPACE" -o json 2>/dev/null \
    | sed -n 's/.*"registry":"\([^"]*\)".*/\1/p' | head -1)" || true
  if [ -n "$detected" ]; then
    REGISTRY="$detected"
    log "reusing registry from the deployed release: $REGISTRY"
  fi
fi

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
[ -n "$VALUES" ] || die "no values file known.
       First install:  cp values.example.yaml /opt/mxid/values.yaml && edit it,
                       then re-run with --values /opt/mxid/values.yaml
       (it is remembered afterwards, so upgrades need no arguments)"
[ -f "$VALUES" ] || die "values file not found: $VALUES
       Keep it OUTSIDE the bundle directory — bundles are disposable and get
       replaced on every upgrade."
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
  esac || die "push to $dst failed.
       - authenticated?  docker login ${REGISTRY%%/*}
       - on Harbor the PROJECT must exist first (it is not auto-created):
         create the '${REGISTRY#*/}' project in the Harbor UI, then re-run
       - self-signed CA? add it to the container runtime's trust store"
}

BACKEND_NAME="${MXID_BACKEND_IMAGE##*/}"   # mxid-ee:v1.8.0
WEB_NAME="${MXID_WEB_IMAGE##*/}"           # mxid-web:v1.8.0
DEPS_NAME="${MXID_DEPS_IMAGE##*/}"         # busybox:1.37

push_one "$MXID_BACKEND_IMAGE" "$BACKEND_NAME"
push_one "$MXID_WEB_IMAGE"     "$WEB_NAME"
push_one "$MXID_DEPS_IMAGE"    "$DEPS_NAME"

# ── helm ─────────────────────────────────────────────────────────────────────
# Shared value overrides. These four are derived from the bundle + --registry,
# so they always win over whatever the values file says — the whole point is
# that images resolve to the registry this cluster can actually reach.
OVERRIDES=(
  --set-string "image.registry=$REGISTRY"
  --set-string "image.tag=$MXID_VERSION"
  --set-string "edition=$MXID_EDITION"
  --set-string "backend.waitForDeps.image=$REGISTRY/$DEPS_NAME"
)

if [ "$DRY_RUN" -eq 1 ]; then
  # `helm template`, NOT `helm upgrade --dry-run`: even with --dry-run=client,
  # upgrade contacts the API server to read release history, so it fails on a
  # machine without cluster access. template renders purely locally, which is
  # what a rehearsal needs — it catches the failures that actually bite
  # (missing secrets, unrenderable values, images left pointing off-site).
  log "rendering (helm template — no cluster contact)"
  RENDER="$(mktemp)"
  helm template "$RELEASE" "$HERE/chart/$MXID_CHART" \
    --namespace "$NAMESPACE" --values "$VALUES" "${OVERRIDES[@]}" > "$RENDER"

  echo
  log "rendered $(grep -c '^---' "$RENDER") manifests. Image references:"
  grep -E '^[[:space:]]+image:' "$RENDER" | sed 's/^ *//' | sort -u | sed 's/^/  /'

  # An image that did not get rewritten is an ImagePullBackOff waiting to
  # happen on a cluster with no route off-site.
  if grep -E '^[[:space:]]+image:' "$RENDER" | grep -qv "$REGISTRY"; then
    rm -f "$RENDER"
    die "some images do NOT point at $REGISTRY (shown above) — they would be unpullable in an air-gapped cluster"
  fi
  rm -f "$RENDER"
  echo
  log "dry run OK — values render and every image resolves to $REGISTRY"
  exit 0
fi

log "helm upgrade --install $RELEASE (namespace $NAMESPACE)"
helm upgrade --install "$RELEASE" "$HERE/chart/$MXID_CHART" \
  --namespace "$NAMESPACE" --create-namespace \
  --values "$VALUES" "${OVERRIDES[@]}"

echo
log "waiting for rollout"
kubectl -n "$NAMESPACE" rollout status "statefulset/$RELEASE-backend" --timeout=5m || \
  warn "backend rollout did not settle — check: kubectl -n $NAMESPACE describe pod -l app.kubernetes.io/name=mxid"
kubectl -n "$NAMESPACE" rollout status "deployment/$RELEASE-web" --timeout=3m || true

# Remember the settings so the next upgrade needs no arguments at all. Written
# after a successful install so a failed run never leaves misleading state.
save_config() {
  local target="$1"
  mkdir -p "$(dirname "$target")" 2>/dev/null || return 1
  cat > "$target" <<EOF || return 1
# MXID site settings — written by install.sh on $MXID_VERSION.
# Lives outside the bundle on purpose: a new bundle must never mean re-entering
# these. Upgrades are then just:  ./install.sh
MXID_SITE_REGISTRY=$REGISTRY
MXID_SITE_VALUES=$(cd "$(dirname "$VALUES")" && pwd)/$(basename "$VALUES")
MXID_SITE_RELEASE=$RELEASE
MXID_SITE_NAMESPACE=$NAMESPACE
EOF
  log "site settings saved to $target"
}
if [ -n "$CONFIG" ]; then
  save_config "$CONFIG" || warn "could not update $CONFIG"
else
  for c in "${DEFAULT_CONFIGS[@]}"; do save_config "$c" && break; done \
    || warn "could not save site settings (not writable) — pass --registry/--values again next time"
fi

echo
log "installed MXID $MXID_EDITION $MXID_VERSION"
echo "Verify:  kubectl -n $NAMESPACE exec statefulset/$RELEASE-backend -- wget -qO- localhost:8080/readyz"
echo "Upgrade: unpack the next bundle and run ./install.sh  (no arguments needed)"
