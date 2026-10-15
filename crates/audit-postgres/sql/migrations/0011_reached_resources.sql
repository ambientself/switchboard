-- What a tool that checks its own scope reached (decision 0011).
--
-- A tool declared `checks_own_scope` cannot say which resources a call reaches until it runs,
-- so its row is begun with the resources "unknown". When it finishes it reports what it
-- reached, and finish writes that list, escaped, capped and counted as begin writes named
-- resources, in place of "unknown", in the same statement as the completion. An empty list
-- says it reached nothing. A row begun with named resources or a reach keeps them.
--
-- 0001 is not edited: applied versions are recorded, and an edit to one would not apply.

-- Completes a call row at most once, and writes nothing else but, for a row begun with
-- unknown resources, the resources its tool reached. As 0006 has it otherwise.
CREATE OR REPLACE FUNCTION switchboard_audit.complete_once() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $complete_once$
BEGIN
    IF OLD.kind IS DISTINCT FROM 'call' THEN
        RAISE EXCEPTION 'audit row % records a listing, which is never completed', OLD.id;
    END IF;
    IF OLD.decision IS DISTINCT FROM 'allow' THEN
        RAISE EXCEPTION 'audit row % records a denial, which is never completed', OLD.id;
    END IF;
    IF OLD.outcome IS NOT NULL THEN
        RAISE EXCEPTION 'audit row % is already complete', OLD.id;
    END IF;
    IF NEW.outcome IS NULL THEN
        RAISE EXCEPTION 'a completion of audit row % has no outcome', OLD.id;
    END IF;
    -- The resources change only from "unknown" to a list, which the table's checks then hold
    -- to their shape. The test is true or false, never NULL: a call row's resources are never
    -- NULL.
    IF (NEW.resources IS DISTINCT FROM OLD.resources
            OR NEW.resources_omitted IS DISTINCT FROM OLD.resources_omitted)
        AND NOT coalesce(
            OLD.resources = '"unknown"'::jsonb AND jsonb_typeof(NEW.resources) = 'array',
            false
        ) THEN
        RAISE EXCEPTION 'audit row % was not begun with unknown resources, so a completion cannot write what its tool reached',
            OLD.id;
    END IF;
    IF to_jsonb(NEW) - ARRAY['outcome', 'outcome_sentence', 'error_kind', 'latency_ms',
                             'finished_at', 'resources', 'resources_omitted']
        IS DISTINCT FROM
       to_jsonb(OLD) - ARRAY['outcome', 'outcome_sentence', 'error_kind', 'latency_ms',
                             'finished_at', 'resources', 'resources_omitted'] THEN
        RAISE EXCEPTION 'only the completion of audit row % may be written', OLD.id;
    END IF;
    NEW.finished_at := clock_timestamp();
    RETURN NEW;
END
$complete_once$;

REVOKE ALL ON FUNCTION switchboard_audit.complete_once() FROM PUBLIC;

-- The gateway's role writes what was reached with the rest of the completion. It does not read
-- it back: a repeated finish is compared on the completion alone, so the role still cannot read
-- what a call named.
GRANT UPDATE (resources, resources_omitted) ON switchboard_audit.call_rows TO switchboard_gateway;
