-- The two roles the audit schema needs, and what each may do with the database.
--
-- Run by an administrator, connected to the database that will hold the audit schema, before
-- the first migration. It can be run again, and in several sessions at once, without failing:
-- each run takes a lock first, so runs take turns, and a role another run created is kept.
--
-- switchboard_owner owns the schema, its tables and its trigger, and runs the migrations.
-- switchboard_gateway is the role the gateway connects as. It gets nothing here beyond
-- connecting; the migrations grant it what it may do on the audit table, column by column.
--
-- Neither role gets a password here. Whoever deploys the gateway sets them from its own
-- secret store. Neither role may create roles or databases, or bypass row security.

DO $roles$
BEGIN
    -- Two runs granting on one database at once update the same catalog row, and the second
    -- fails. The number is any number, the same in every copy of this script, and not the
    -- migrations' lock.
    PERFORM pg_advisory_xact_lock(6005341489043162114);
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
