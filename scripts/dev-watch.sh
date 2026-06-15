#!/bin/sh
# dev-watch.sh — Host-side file watcher for Docker dev containers
# Bridges macOS FSEvents to container inotify via docker cp + touch
#
# Usage: ./scripts/dev-watch.sh
# Requires: fswatch (brew install fswatch)

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v fswatch >/dev/null 2>&1; then
  echo "Error: fswatch not found. Install with: brew install fswatch"
  exit 1
fi

echo "Watching for file changes..."
echo "  Go: internal/ pkg/ cmd/ configs/ → mxid-dev"
echo "  Frontend: web/apps/ web/packages/ → mxid-console, mxid-portal"
echo ""

fswatch -0 -r \
  --exclude '\.git' \
  --exclude 'node_modules' \
  --exclude 'topiam' \
  --exclude 'tmp/' \
  --exclude '\.swp$' \
  --exclude '\.swo$' \
  --exclude '__pycache__' \
  "$PROJECT_ROOT/internal" \
  "$PROJECT_ROOT/pkg" \
  "$PROJECT_ROOT/cmd" \
  "$PROJECT_ROOT/configs" \
  "$PROJECT_ROOT/web/apps" \
  "$PROJECT_ROOT/web/packages" \
| while IFS= read -r -d '' file; do
  # Get relative path
  rel="${file#$PROJECT_ROOT/}"

  case "$rel" in
    internal/*|pkg/*|cmd/*|configs/*|.air.toml)
      container_path="/app/$rel"
      echo "[Go] $rel → mxid-dev:$container_path"
      docker cp "$file" "mxid-dev:$container_path" 2>/dev/null
      docker exec mxid-dev touch "$container_path" 2>/dev/null
      ;;
    web/apps/console/*|web/packages/shared/*)
      container_path="/app/$rel"
      echo "[Console] $rel → mxid-console:$container_path"
      docker cp "$file" "mxid-console:$container_path" 2>/dev/null
      docker exec mxid-console touch "$container_path" 2>/dev/null
      ;;
    web/apps/portal/*|web/packages/shared/*)
      container_path="/app/$rel"
      echo "[Portal] $rel → mxid-portal:$container_path"
      docker cp "$file" "mxid-portal:$container_path" 2>/dev/null
      docker exec mxid-portal touch "$container_path" 2>/dev/null
      ;;
  esac
done
