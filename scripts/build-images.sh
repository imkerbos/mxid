#!/usr/bin/env bash
#
# build-images.sh — build the MXID images from source and push them to your
# own registry. The alternative to scripts/sync-images.sh: same result, but the
# images come from your checkout instead of GHCR. Use it when you cannot pull
# the released images, when you carry local patches, or when policy requires
# building from reviewed source.
#
# Sources it can build from, in order of what it finds:
#   1. missing        -> cloned for you at the requested tag
#   2. a git clone    -> fetched and checked out to the requested tag
#   3. a ZIP download -> built as-is (no .git, so the version is whatever you
#                        extracted). Extract and RENAME the folders to exactly
#                        `mxid` and `mxid-ee`: the go.mod `replace => ../mxid`
#                        and the EE Dockerfile's COPY depend on those names.
#
# Layout (both repos side by side):
#   workdir/
#   ├── mxid/        CE source (public)
#   └── mxid-ee/     EE source (private; only needed for --ee)
#
# Run it from either place — inside the CE checkout, or beside the two folders:
#   ./mxid/scripts/build-images.sh v1.8.0 harbor.example.com/sa02
#   ./build-images.sh v1.8.0 harbor.example.com/sa02          # copied out
#
# Options:
#   --ce         build the CE backend instead of EE (no mxid-ee needed)
#   --no-push    build only, don't push
#   --with-deps  also mirror busybox (the chart's waitForDeps init container)
#   --no-clone   fail instead of cloning missing sources
#
# Environment overrides:
#   MXID_REGISTRY   default registry/project, so you can omit the 2nd argument
#   MXID_CE_REPO    default https://github.com/imkerbos/mxid.git
#   MXID_EE_REPO    default https://github.com/imkerbos/mxid-ee.git
#                   (point these at the matrixplusio mirror if you use it)
#
# Authentication is yours to arrange, and is needed twice:
#   GitHub   — for cloning, especially the PRIVATE mxid-ee repo.
#              `gh auth login` (HTTPS), a credential helper, or switch the URLs
#              above to SSH (git@github.com:...).
#   Registry — `podman login <host>` / `docker login <host>` before pushing.
# podman is used when present, otherwise docker.
set -euo pipefail

VERSION="${1:-}"
REGISTRY="${2:-${MXID_REGISTRY:-}}"
if [ -z "$VERSION" ] || [ -z "$REGISTRY" ]; then
  echo "usage: $0 <version> <registry/project> [--ce] [--no-push] [--with-deps]" >&2
  echo "   eg: $0 v1.8.0 harbor.example.com/sa02" >&2
  exit 1
fi
[ $# -ge 2 ] && shift 2 || shift 1

EDITION=ee
PUSH=1
WITH_DEPS=0
CLONE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --ce) EDITION=ce; shift ;;
    --ee) EDITION=ee; shift ;;
    --no-push) PUSH=0; shift ;;
    --with-deps) WITH_DEPS=1; shift ;;
    --no-clone) CLONE=0; shift ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

CE_REPO="${MXID_CE_REPO:-https://github.com/imkerbos/mxid.git}"
EE_REPO="${MXID_EE_REPO:-https://github.com/imkerbos/mxid-ee.git}"

log() { printf '\033[1;36m>>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# podman first — that is what the air-gapped build hosts run. Falls back to
# docker so the same script works on a laptop.
if command -v podman >/dev/null; then ENGINE=podman
elif command -v docker >/dev/null; then ENGINE=docker
else die "need podman or docker"; fi

# Locate the two source trees. The script may sit inside the CE checkout
# (mxid/scripts/) or be copied next to the folders — resolve both.
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF_HOSTED=0    # 1 = this script lives inside the CE tree it would check out
if [ -f "$SELF/../deploy/dockerfile/Dockerfile.web" ]; then
  CE_DIR="$(cd "$SELF/.." && pwd)"            # running from inside mxid/
  SELF_HOSTED=1
else
  CE_DIR="$(cd "$SELF" && pwd)/mxid"          # running beside mxid/ and mxid-ee/
fi
PARENT="$(dirname "$CE_DIR")"
EE_DIR="$PARENT/mxid-ee"

# Bring one source tree to $VERSION: clone it if absent, fetch+checkout if it is
# a git tree, leave it alone if it is a ZIP extract (no .git — the version is
# whatever was downloaded, and failing on that would be unhelpful).
prepare_src() {
  local dir="$1" url="$2" name="$3" marker="$4"
  if [ ! -d "$dir" ]; then
    [ "$CLONE" -eq 1 ] || die "missing $dir and --no-clone was given"
    log "cloning $name $VERSION -> $dir"
    git clone --depth 1 --branch "$VERSION" "$url" "$dir" 2>&1 | sed 's/^/   /' || die \
      "clone failed: $url @ $VERSION
       - does the tag exist in that repo?
       - private repo? authenticate first: gh auth login, a git credential
         helper, or set ${name}_REPO to an SSH URL (git@github.com:...)
       - or place the source at $dir yourself (a GitHub ZIP works; rename the
         folder to exactly $(basename "$dir"))"
  elif [ -d "$dir/.git" ]; then
    log "git: updating $name -> $VERSION"
    git -C "$dir" fetch --tags --prune origin
    git -C "$dir" checkout -q "$VERSION" || die "$name has no tag $VERSION"
  else
    log "$name has no .git (ZIP download) — building the on-disk source as-is"
  fi
  # Check for the source file, not for .git — ZIP downloads have no .git.
  [ -f "$dir/$marker" ] || die "missing $dir/$marker — is that really the $name source?"
}

if [ "$SELF_HOSTED" -eq 1 ]; then
  # Never git-checkout the tree this script is executing from: it would swap the
  # source (and this file) mid-run, and would fail outright against uncommitted
  # work. Build what is on disk and say so.
  log "running from inside the CE checkout — building it as-is, not switching to $VERSION"
  [ -f "$CE_DIR/deploy/dockerfile/Dockerfile.web" ] \
    || die "missing $CE_DIR/deploy/dockerfile/Dockerfile.web"
else
  prepare_src "$CE_DIR" "$CE_REPO" MXID_CE deploy/dockerfile/Dockerfile.web
fi
if [ "$EDITION" = ee ]; then
  prepare_src "$EE_DIR" "$EE_REPO" MXID_EE deploy/Dockerfile
fi

if [ "$EDITION" = ee ] && [ -d "$EE_DIR/.git" ]; then
  COMMIT="$(git -C "$EE_DIR" rev-parse --short HEAD)"
elif [ -d "$CE_DIR/.git" ]; then
  COMMIT="$(git -C "$CE_DIR" rev-parse --short HEAD)"
else
  COMMIT="zip-$VERSION"
fi
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BACKEND=$([ "$EDITION" = ce ] && echo mxid || echo mxid-ee)

log "engine=$ENGINE  version=$VERSION  commit=$COMMIT  edition=$EDITION"
log "images: $REGISTRY/$BACKEND:$VERSION  +  $REGISTRY/mxid-web:$VERSION"

# The web image is edition-independent — edition is gated at runtime through
# /system/info, so CE and EE share one nginx+SPA image. Context = CE repo root.
log "building mxid-web ..."
$ENGINE build --platform linux/amd64 \
  -f "$CE_DIR/deploy/dockerfile/Dockerfile.web" \
  --build-arg VERSION="$VERSION" \
  --build-arg COMMIT="$COMMIT" \
  --build-arg BUILD_TIME="$BUILD_TIME" \
  -t "$REGISTRY/mxid-web:$VERSION" \
  "$CE_DIR"

# amd64 only: garble under arm64 emulation is impractically slow, and an image
# the cluster cannot run is worse than a slow build.
if [ "$EDITION" = ee ]; then
  log "building mxid-ee (garble-obfuscated, amd64 — this takes a while) ..."
  # Context is the PARENT dir so the Dockerfile's COPY mxid/ + COPY mxid-ee/
  # and the go.mod replace ../mxid all resolve.
  $ENGINE build --platform linux/amd64 \
    -f "$EE_DIR/deploy/Dockerfile" \
    --build-arg VERSION="$VERSION" \
    --build-arg COMMIT="$COMMIT" \
    --build-arg BUILD_TIME="$BUILD_TIME" \
    -t "$REGISTRY/mxid-ee:$VERSION" \
    "$PARENT"
else
  log "building mxid (CE backend) ..."
  $ENGINE build --platform linux/amd64 \
    -f "$CE_DIR/deploy/dockerfile/Dockerfile" \
    --build-arg VERSION="$VERSION" \
    --build-arg COMMIT="$COMMIT" \
    --build-arg BUILD_TIME="$BUILD_TIME" \
    -t "$REGISTRY/mxid:$VERSION" \
    "$CE_DIR"
fi

IMAGES=("$REGISTRY/mxid-web:$VERSION" "$REGISTRY/$BACKEND:$VERSION")

# busybox is upstream, so it is mirrored rather than built. Off by default:
# point backend.waitForDeps.image at any busybox you already have, or set
# backend.waitForDeps.enabled=false.
if [ "$WITH_DEPS" -eq 1 ]; then
  log "mirroring busybox:1.37 (waitForDeps init container)"
  $ENGINE pull --platform linux/amd64 busybox:1.37
  $ENGINE tag busybox:1.37 "$REGISTRY/busybox:1.37"
  IMAGES+=("$REGISTRY/busybox:1.37")
fi

if [ "$PUSH" -eq 0 ]; then
  log "built, not pushed (--no-push):"
  printf '   %s\n' "${IMAGES[@]}"
  exit 0
fi

log "pushing ..."
for img in "${IMAGES[@]}"; do
  $ENGINE push "$img" || die "push to $img failed.
       - logged in?  $ENGINE login ${REGISTRY%%/*}
       - on Harbor the project must exist first (it is not auto-created)"
done

echo
log "done:"
printf '   %s\n' "${IMAGES[@]}"
cat <<EOF

Now upgrade:

  helm upgrade --install mxid deploy/helm/mxid -n mxid -f values.yaml \\
    --set image.registry=$REGISTRY \\
    --set image.tag=$VERSION \\
    --set edition=$EDITION
EOF
