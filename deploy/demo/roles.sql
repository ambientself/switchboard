-- The demo's database roles and database. Run by migrate.sh as the Postgres superuser, before
-- the audit migrations. Safe to run again. The passwords arrive as psql variables and are dummy
-- values from the demo's configuration; nothing here is a real credential.
--
--   switchboard_owner    owns the database and the audit schema; runs the migrations
--   switchboard_gateway  the gateway's role; the migrations grant it what it needs, and no more
--   switchboard_reader   reads audit rows for the demo's closing query
--
-- The first two are the roles crates/audit-postgres names (OWNER_ROLE and GATEWAY_ROLE). Its own
-- sql/roles.sql creates them too, with no password; this file also sets the dummy passwords,
-- creates the reader and the database, and takes every privilege on the database from PUBLIC.
-- The gateway checks its role at boot and refuses to start if it can do more than it needs.

\set ON_ERROR_STOP on

SELECT format('CREATE ROLE %I LOGIN', name)
  FROM (VALUES ('switchboard_owner'), ('switchboard_gateway'), ('switchboard_reader')) AS r(name)
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = name)
\gexec

ALTER ROLE switchboard_owner NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'owner_password';
ALTER ROLE switchboard_gateway NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'gateway_password';
ALTER ROLE switchboard_reader NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'reader_password';

SELECT 'CREATE DATABASE switchboard OWNER switchboard_owner'
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'switchboard')
\gexec

REVOKE ALL ON DATABASE switchboard FROM PUBLIC;
GRANT CONNECT ON DATABASE switchboard TO switchboard_gateway, switchboard_reader;
