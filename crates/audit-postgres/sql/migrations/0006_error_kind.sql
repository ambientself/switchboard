-- The kind of an error (decisions 0009 and 0011): invalid arguments, an oversized or late result
-- from a `read` tool, a custodian refusal, a vendor refusal, or another failure. An error row
-- keeps no sentence, so without its kind a vendor's refusal could not be told from any other
-- failure. A row has a kind exactly when its outcome is `error`.
--
-- 0001 is not edited: applied versions are recorded, and an edit to one would not apply.

ALTER TABLE switchboard_audit.call_rows
    ADD COLUMN error_kind text;

-- Error rows written before this migration have no recorded kind, and say so. The update
-- writes a column other than the completion, which complete_once refuses for every role, so
-- that trigger is off for this statement only. ALTER TABLE holds the table's lock until the
-- migration commits, so no other session writes while it is off.
ALTER TABLE switchboard_audit.call_rows DISABLE TRIGGER complete_once;
UPDATE switchboard_audit.call_rows
    SET error_kind = 'before-0006'
    WHERE outcome = 'error';
ALTER TABLE switchboard_audit.call_rows ENABLE TRIGGER complete_once;

ALTER TABLE switchboard_audit.call_rows
    ADD CONSTRAINT error_kind_known CHECK (error_kind IN (
        'invalid_arguments', 'oversized_or_late_read', 'custodian_refusal', 'vendor_refusal',
        'other', 'before-0006'
    )),
    -- An error has a kind, and nothing else does: not another outcome, and not a row with no
    -- outcome yet. Each side is true or false, never NULL, so a missing value fails the check
    -- rather than passing it.
    ADD CONSTRAINT error_kind_shape CHECK (
        coalesce(outcome = 'error', false) = (error_kind IS NOT NULL)
    );

-- Completes a call row at most once, and writes nothing else. As 0004 has it, with the error
-- kind now one of the completion's columns.
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
    IF to_jsonb(NEW) - ARRAY['outcome', 'outcome_sentence', 'error_kind', 'latency_ms',
                             'finished_at']
        IS DISTINCT FROM
       to_jsonb(OLD) - ARRAY['outcome', 'outcome_sentence', 'error_kind', 'latency_ms',
                             'finished_at'] THEN
        RAISE EXCEPTION 'only the completion of audit row % may be written', OLD.id;
    END IF;
    NEW.finished_at := clock_timestamp();
    RETURN NEW;
END
$complete_once$;

REVOKE ALL ON FUNCTION switchboard_audit.complete_once() FROM PUBLIC;

-- The gateway's role writes the kind with the rest of the completion, and reads it back to
-- compare a repeated finish with the one stored.
GRANT UPDATE (error_kind) ON switchboard_audit.call_rows TO switchboard_gateway;
GRANT SELECT (error_kind) ON switchboard_audit.call_rows TO switchboard_gateway;
