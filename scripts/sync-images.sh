#!/usr/bin/env bash
# sync-images.sh — copy the release images from GHCR into your own registry.
#
# For the normal restricted setup: the CLUSTER can't reach ghcr.io, but one
# machine (your laptop, a jump box, a CI runner) can reach both ghcr.io and
# your registry. Run it there.
#
#   docker login harbor.internal            # once — your own registry
#   docker login ghcr.io                    # ONLY for --ee; the EE image is
#                                           # private. The CE image is public
#                                           # and pulls with no credentials.
#   ./scripts/sync-images.sh v1.8.0 harbor.internal/mxid        # EE
#   ./scripts/sync-images.sh v1.8.0 harbor.internal/mxid --ce   # CE, no GitHub login
#
# Then upgrade with helm as usual:
#   helm upgrade --install mxid deploy/helm/mxid -n mxid -f values.yaml \
#     --set image.registry=harbor.internal/mxid --set image.tag=v1.8.0
#
# If NO machine can reach both, use scripts/offline-bundle.sh instead — it
# produces a single tarball to carry in by hand.
set -euo pipefail

VERSION="${1:?usage: $0 vX.Y.Z <registry/namespace> [--ce]}"
REGISTRY="${2:?usage: $0 vX.Y.Z <registry/namespace> [--ce]}"
EDITION="${3:---ee}"

SRC="${MXID_SRC_REGISTRY:-ghcr.io/imkerbos}"
BACKEND=$([ "$EDITION" = "--ce" ] && echo mxid || echo mxid-ee)

# busybox is the chart's waitForDeps init container. Forget it and every pod
# sits in Init:ImagePullBackOff on a cluster that can't reach Docker Hub.
IMAGES=("$BACKEND:$VERSION" "mxid-web:$VERSION")
DEPS="busybox:1.37"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

for img in "${IMAGES[@]}"; do
  log "$SRC/$img  ->  $REGISTRY/$img"
  # linux/amd64: the garble-obfuscated EE backend is amd64-only, so pinning the
  # platform stops an arm64 machine from mirroring images the cluster can't run.
  docker pull --platform linux/amd64 "$SRC/$img"
  docker tag "$SRC/$img" "$REGISTRY/$img"
  docker push "$REGISTRY/$img"
done

log "$DEPS  ->  $REGISTRY/$DEPS"
docker pull --platform linux/amd64 "$DEPS"
docker tag "$DEPS" "$REGISTRY/$DEPS"
docker push "$REGISTRY/$DEPS"

cat <<EOF

Done. Now upgrade:

  helm upgrade --install mxid deploy/helm/mxid -n mxid -f values.yaml \\
    --set image.registry=$REGISTRY \\
    --set image.tag=$VERSION \\
    --set edition=$([ "$EDITION" = "--ce" ] && echo ce || echo ee) \\
    --set backend.waitForDeps.image=$REGISTRY/$DEPS
EOF
