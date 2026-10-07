#!/bin/sh
# deploy/demo/migrate.sh: prepares the demo database. It creates the roles and the database as
# the Postgres superuser, applies each audit migration once as switchboard_owner, and lets
# switchboard_reader read the audit schema. Any failure stops it with a non-zero exit.
#
# Environment (every value is a dummy from the demo's configuration):
#   PGHOST, PGPORT            where Postgres listens (PGPORT defaults to 5432)
#   POSTGRES_PASSWORD         the superuser's password
#   OWNER_PASSWORD, GATEWAY_PASSWORD, READER_PASSWORD
#   MIGRATIONS_DIR            default /usr/share/switchboard/migrations
#   ROLES_SQL                 default /usr/share/switchboard/roles.sql
#   WAIT_SECONDS              how long to wait for Postgres to accept connections, default 60
set -eu

: "${PGHOST:?PGHOST is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${OWNER_PASSWORD:?OWNER_PASSWORD is required}"
: "${GATEWAY_PASSWORD:?GATEWAY_PASSWORD is required}"
: "${READER_PASSWORD:?READER_PASSWORD is required}"
MIGRATIONS_DIR=${MIGRATIONS_DIR:-/usr/share/switchboard/migrations}
ROLES_SQL=${ROLES_SQL:-/usr/share/switchboard/roles.sql}
WAIT_SECONDS=${WAIT_SECONDS:-60}
export PGPORT="${PGPORT:-5432}"
# Notices such as "already exists, skipping" are not news on a second run.
export PGOPTIONS='-c client_min_messages=warning'
# TODO(integration): the audit schema name follows planDemo.md (#10a).
AUDIT_SCHEMA=${AUDIT_SCHEMA:-switchboard_audit}

as_superuser() { PGPASSWORD=$POSTGRES_PASSWORD psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres "$@"; }
as_owner() { PGPASSWORD=$OWNER_PASSWORD psql -X -q -v ON_ERROR_STOP=1 -U switchboard_owner -d switchboard "$@"; }

waited=0
until pg_isready -q -U postgres -d postgres; do
  if [ "$waited" -ge "$WAIT_SECONDS" ]; then
    echo "migrate: Postgres at $PGHOST:$PGPORT did not accept connections within ${WAIT_SECONDS}s" >&2
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done

as_superuser -v owner_password="$OWNER_PASSWORD" -v gateway_password="$GATEWAY_PASSWORD" \
  -v reader_password="$READER_PASSWORD" -f "$ROLES_SQL"
echo "migrate: roles and database ready"

found=0
for file in "$MIGRATIONS_DIR"/*.sql; do
  [ -f "$file" ] && found=$((found + 1))
done
if [ "$found" -eq 0 ]; then
  echo "migrate: no migrations in $MIGRATIONS_DIR; the image was built without the audit schema" >&2
  exit 1
fi

as_owner -c "CREATE TABLE IF NOT EXISTS public.switchboard_migrations (
  name text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now())"

applied=0
skipped=0
for file in "$MIGRATIONS_DIR"/*.sql; do
  name=$(basename "$file")
  done_already=$(as_owner -At -v name="$name" -f - <<'SQL'
SELECT count(*) FROM public.switchboard_migrations WHERE name = :'name';
SQL
)
  if [ "$done_already" = "1" ]; then
    skipped=$((skipped + 1))
    continue
  fi
  # The migration and its record commit together, or neither does.
  { cat "$file"; printf '\nINSERT INTO public.switchboard_migrations (name) VALUES (:%s);\n' "'name'"; } \
    | as_owner --single-transaction -v name="$name" -f -
  echo "migrate: applied $name"
  applied=$((applied + 1))
done

as_owner -v schema="$AUDIT_SCHEMA" -f - <<'SQL'
GRANT USAGE ON SCHEMA :"schema" TO switchboard_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA :"schema" TO switchboard_reader;
SQL
echo "migrate: $applied applied, $skipped already applied; switchboard_reader may read $AUDIT_SCHEMA"
