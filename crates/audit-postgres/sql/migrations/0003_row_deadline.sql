-- Each row records the instance that began it, its kind, and a deadline (decision 0009, "What
-- begin guarantees"). The gateway supplies the allowance: its begin budget, the call's
-- deadline and its finish deadline. The trigger set_times sets the deadline from the
-- database's clock and that allowance, for every role, whatever the insert carried. A row of
-- kind 'call' cannot be stored without a deadline; a row of kind 'list' has none.
--
-- 0001 is not edited: applied versions are recorded, and an edit to one would not apply.

ALTER TABLE switchboard_audit.call_rows
    ADD COLUMN instance     text,
    ADD COLUMN kind         text,
    ADD COLUMN allowance_ms bigint,
    ADD COLUMN deadline     timestamptz;

-- Rows written before this migration were all calls, by an instance nobody recorded. Their
-- deadline is when they were completed, or begun if they never were, so none of them reads as
-- open for longer than it already has. The update writes columns other than the completion,
-- which complete_once refuses for every role, so that trigger is off for this statement only.
-- ALTER TABLE holds the table's lock until the migration commits, so no other session writes
-- while it is off.
ALTER TABLE switchboard_audit.call_rows DISABLE TRIGGER complete_once;
UPDATE switchboard_audit.call_rows
    SET instance = 'before-0003',
        kind = 'call',
        allowance_ms = 0,
        deadline = coalesce(finished_at, begun_at);
ALTER TABLE switchboard_audit.call_rows ENABLE TRIGGER complete_once;

ALTER TABLE switchboard_audit.call_rows
    ALTER COLUMN instance SET NOT NULL,
    ALTER COLUMN kind SET NOT NULL,
    ADD CONSTRAINT kind_known CHECK (kind IN ('call', 'list')),
    ADD CONSTRAINT allowance_shape CHECK (allowance_ms >= 0),
    -- A call has a deadline and a listing has none. With the trigger below, a call inserted
    -- without an allowance has no deadline, so it is refused here.
    ADD CONSTRAINT deadline_shape CHECK ((kind = 'call') = (deadline IS NOT NULL));

-- Sets the time at begin and the deadline from the database's clock at insert, overwriting
-- anything the insert carried, for every role. A row is begun now. A call's deadline is that
-- time plus its allowance; a listing has none. A row written complete at insert, which only
-- the owner can write, is complete at the moment it is begun.
CREATE OR REPLACE FUNCTION switchboard_audit.set_times() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $set_times$
BEGIN
    NEW.begun_at := clock_timestamp();
    NEW.finished_at := CASE WHEN NEW.outcome IS NULL THEN NULL ELSE NEW.begun_at END;
    NEW.deadline := CASE WHEN NEW.kind = 'call'
        THEN NEW.begun_at + NEW.allowance_ms * interval '1 millisecond' END;
    RETURN NEW;
END
$set_times$;

REVOKE ALL ON FUNCTION switchboard_audit.set_times() FROM PUBLIC;

-- The gateway's role writes the instance, the kind and the allowance, and reads the kind and
-- the deadline, which the open-row query needs. It writes neither time.
GRANT INSERT (instance, kind, allowance_ms) ON switchboard_audit.call_rows TO switchboard_gateway;
GRANT SELECT (kind, deadline) ON switchboard_audit.call_rows TO switchboard_gateway;
