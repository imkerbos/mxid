#!/usr/bin/env bash
#
# Back up an MXID database to a single compressed file.
#
# A backup nobody has restored is a hope, not a backup — so `restore` is part of
# this script rather than a paragraph in a runbook, and `verify` restores into a
# throwaway database and checks the result rather than trusting the file's size.
#
#   ./scripts/backup.sh dump                      → mxid-YYYYmmdd-HHMMSS.dump
#   ./scripts/backup.sh verify <file>             → restore to a scratch DB, check, drop
#   ./scripts/backup.sh restore <file> <database> → restore for real (asks first)
#
# Connection comes from the standard libpq variables, so it works the same
# against a container, a managed instance or a socket:
#
#   PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE
#
# WHAT A DUMP DOES NOT CONTAIN, and what that means for a restore:
#
#   * The encryption keys. Every secret in the database (OIDC signing keys, IdP
#     client secrets, form-fill credentials) is encrypted with
#     MXID_CRYPTO_KEY_ENCRYPTION_KEY, which lives in the environment and never
#     in the database. Restoring without the same KEK gives you rows you cannot
#     decrypt. Back the KEK up separately, and somewhere else.
#   * Redis. Sessions, tickets and rate-limit counters are deliberately not
#     durable; a restore signs everybody out, which is the correct outcome.
#   * The EE licence fingerprint. A logical restore into a NEW cluster changes
#     PostgreSQL's system_identifier, so an EE licence must be re-activated
#     afterwards (Console → Settings → License). Physical replication and
#     failover keep it.
set -euo pipefail

BLUE=$'\033[1;36m'; GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; YELLOW=$'\033[1;33m'; OFF=$'\033[0m'
say()  { printf "%s[backup]%s %s\n" "$BLUE" "$OFF" "$*" >&2; }
ok()   { printf "  %s✓%s %s\n" "$GREEN" "$OFF" "$*" >&2; }
warn() { printf "  %s!%s %s\n" "$YELLOW" "$OFF" "$*" >&2; }
die()  { printf "%s✗ %s%s\n" "$RED" "$*" "$OFF" >&2; exit 1; }

DB="${PGDATABASE:-mxid}"
OUT_DIR="${MXID_BACKUP_DIR:-.}"

need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found in PATH"; }

# The custom format is what makes a restore selective and parallel; a plain SQL
# file cannot skip a table or rebuild indexes concurrently.
cmd_dump() {
  need pg_dump
  local stamp file
  stamp="$(date +%Y%m%d-%H%M%S)"
  file="${OUT_DIR%/}/mxid-${stamp}.dump"

  say "dumping ${DB} → ${file}"
  pg_dump --format=custom --compress=9 --no-owner --no-privileges \
          --dbname="$DB" --file="$file"

  ok "$(du -h "$file" | cut -f1) written"
  warn "the encryption key (MXID_CRYPTO_KEY_ENCRYPTION_KEY) is NOT in this file — back it up separately, or the secrets restore as unreadable bytes"
  printf "%s\n" "$file"
}

# The check that matters: not "did a file appear" but "does that file rebuild a
# database that MXID would accept". Restores into a scratch database, asserts the
# schema version and a couple of tables that must never be empty, then drops it.
cmd_verify() {
  need pg_restore; need psql
  local file="${1:?usage: backup.sh verify <file>}"
  [[ -f "$file" ]] || die "no such file: $file"

  local scratch="mxid_verify_$$"
  say "restoring ${file} into scratch database ${scratch}"
  # shellcheck disable=SC2064
  trap "psql --dbname=postgres --quiet --command='DROP DATABASE IF EXISTS ${scratch};' >/dev/null 2>&1 || true" EXIT

  psql --dbname=postgres --quiet --command="CREATE DATABASE ${scratch};" >/dev/null
  pg_restore --dbname="$scratch" --no-owner --no-privileges --exit-on-error "$file" >/dev/null

  local version users
  version="$(psql --dbname="$scratch" --tuples-only --no-align \
    --command='SELECT version FROM schema_migrations LIMIT 1;' 2>/dev/null || true)"
  [[ -n "$version" ]] || die "restored database has no schema_migrations row — this dump is not an MXID database"
  ok "schema version ${version}"

  users="$(psql --dbname="$scratch" --tuples-only --no-align \
    --command='SELECT count(*) FROM mxid_user;' 2>/dev/null || echo 0)"
  [[ "$users" -gt 0 ]] || die "restored database contains no users — the dump is structurally valid but empty"
  ok "${users} user(s)"

  for t in mxid_app mxid_audit_log mxid_role; do
    psql --dbname="$scratch" --tuples-only --no-align \
      --command="SELECT 1 FROM ${t} LIMIT 1;" >/dev/null 2>&1 \
      || die "table ${t} is missing from the restore"
  done
  ok "core tables present"

  printf "%s✓ %s restores cleanly%s\n" "$GREEN" "$file" "$OFF" >&2
}

cmd_restore() {
  need pg_restore; need psql
  local file="${1:?usage: backup.sh restore <file> <database>}"
  local target="${2:?usage: backup.sh restore <file> <database>}"
  [[ -f "$file" ]] || die "no such file: $file"

  # --clean drops every object it is about to recreate. Say so plainly rather
  # than discovering it afterwards.
  printf "%sThis REPLACES the contents of database '%s' with '%s'. Existing data in it is destroyed.%s\n" \
    "$YELLOW" "$target" "$file" "$OFF" >&2
  read -r -p "Type the database name to confirm: " confirm
  [[ "$confirm" == "$target" ]] || die "aborted"

  say "restoring into ${target}"
  pg_restore --dbname="$target" --clean --if-exists --no-owner --no-privileges \
             --exit-on-error "$file"

  ok "restored"
  warn "MXID must be restarted so it reconnects and re-reads settings"
  warn "sessions are gone (they live in Redis) — everybody signs in again, which is intended"
  warn "restored into a NEW cluster? PostgreSQL's system_identifier changed, so an EE licence needs re-activating: Console → Settings → License"
}

case "${1:-}" in
  dump)    shift; cmd_dump "$@" ;;
  verify)  shift; cmd_verify "$@" ;;
  restore) shift; cmd_restore "$@" ;;
  *)
    cat >&2 <<EOF
usage: $(basename "$0") <command>

  dump                       write mxid-<timestamp>.dump (custom format)
  verify <file>              restore into a scratch database and check it, then drop it
  restore <file> <database>  restore for real — destroys the target's contents

Connection uses the standard libpq variables: PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE
Output directory: MXID_BACKUP_DIR (default: current directory)
EOF
    exit 2
    ;;
esac
