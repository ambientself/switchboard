-- The two roles the audit schema needs, and what each may do with the database.
--
-- Run by an administrator, connected to the database that will hold the audit schema, before
-- the first migration. Roles belong to the whole server, so this can be run again, and by two
-- sessions at once, without failing.
--
-- switchboard_owner owns the schema, its tables and its trigger, and runs the migrations.
-- switchboard_gateway is the role the gateway connects as. It gets nothing here beyond
-- connecting; the migrations grant it what it may do on the audit table, column by column.
--
-- Neither role gets a password here. Whoever deploys the gateway sets them from its own
-- secret store. Neither role may create roles or databases, or bypass row security.

DO $roles$
BEGIN
    BEGIN
        CREATE ROLE switchboard_owner
            LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN
        RAISE NOTICE 'role switchboard_owner already exists';
    END;
    BEGIN
        CREATE ROLE switchboard_gateway
            LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN
        RAISE NOTICE 'role switchboard_gateway already exists';
    END;
    -- The owner creates the audit schema in this database. The gateway only connects.
    EXECUTE format('GRANT CONNECT, CREATE ON DATABASE %I TO switchboard_owner', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO switchboard_gateway', current_database());
END
$roles$;
