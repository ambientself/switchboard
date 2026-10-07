#!/bin/sh
# deploy/demo/migrate.sh: prepares the demo database. It creates the roles and the database as
# the Postgres superuser, has `switchboard migrate` apply the audit migrations as
# switchboard_owner, and lets switchboard_reader read the audit schema. Any failure stops it
# with a non-zero exit.
#
# The migrations are the audit store's own (crates/audit-postgres), built into the switchboard
# binary: `switchboard migrate` applies each one not yet recorded in
# switchboard_audit.migrations, in one transaction with its record.
#
# Environment (every value is a dummy from the demo's configuration):
#   PGHOST, PGPORT            where Postgres listens (PGPORT defaults to 5432)
#   POSTGRES_PASSWORD         the superuser's password
#   OWNER_PASSWORD, GATEWAY_PASSWORD, READER_PASSWORD
#   ROLES_SQL                 default /usr/share/switchboard/roles.sql
#   WAIT_SECONDS              how long to wait for Postgres to accept connections, default 60
set -eu

: "${PGHOST:?PGHOST is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${OWNER_PASSWORD:?OWNER_PASSWORD is required}"
: "${GATEWAY_PASSWORD:?GATEWAY_PASSWORD is required}"
: "${READER_PASSWORD:?READER_PASSWORD is required}"
ROLES_SQL=${ROLES_SQL:-/usr/share/switchboard/roles.sql}
WAIT_SECONDS=${WAIT_SECONDS:-60}
export PGPORT="${PGPORT:-5432}"
# Notices such as "already exists, skipping" are not news on a second run.
export PGOPTIONS='-c client_min_messages=warning'
# The schema crates/audit-postgres creates (audit_postgres::SCHEMA).
AUDIT_SCHEMA=switchboard_audit

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

# The password is a dummy, and the URL never leaves this container's environment.
SWITCHBOARD_MIGRATE_DATABASE_URL="postgres://switchboard_owner:$OWNER_PASSWORD@$PGHOST:$PGPORT/switchboard" \
  switchboard migrate

as_owner -v schema="$AUDIT_SCHEMA" -f - <<'SQL'
GRANT USAGE ON SCHEMA :"schema" TO switchboard_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA :"schema" TO switchboard_reader;
SQL
echo "migrate: switchboard_reader may read $AUDIT_SCHEMA"
