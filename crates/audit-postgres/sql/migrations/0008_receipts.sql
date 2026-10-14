-- Receipts for side effects (decision 0009, part 2). A receipt is the gateway's durable record
-- of one call of a tool not classified `read`. It is reserved as `pending` in the same
-- transaction as its call's row, and its key is unique in its scope, so that of two calls with
-- one key in one scope exactly one reserves. A call whose key already has a receipt does not
-- run: its row is written complete at begin, `refused` or `duplicate`, in the same transaction
-- as the check. Finish settles the receipt in the same transaction as the row's completion,
-- while the row's deadline has not passed by the database's clock.
--
-- The receipt holds what the core's `Receipt` holds. The vendor target and the lookups made
-- are not here: reconciliation adds them.
--
-- 0001 is not edited: applied versions are recorded, and an edit to one would not apply.

CREATE TABLE switchboard_audit.receipts (
    -- The row that reserved it, which is also the receipt's identifier.
    row_id             uuid        PRIMARY KEY REFERENCES switchboard_audit.call_rows (id),
    -- The database's time at the reservation, set by the trigger receipt_moves for every
    -- role. The age of the oldest receipt in `unknown` is counted from it.
    reserved_at        timestamptz NOT NULL,

    -- Where the key is unique: the proved principal's issuer and subject, and the
    -- delegation's identifying fields when a delegation is present and carries them.
    principal_issuer   text        NOT NULL,
    principal_subject  text        NOT NULL,
    delegation_scope   text,
    idempotency_key    text        NOT NULL,

    tool               text        NOT NULL,
    tool_use_id        text,
    -- SHA-256 over the call's arguments in canonical form, as 64 lowercase hex digits.
    digest             text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    -- The resources the call named, as its row records them: an array of named resources,
    -- "unknown", or a reach naming its entry.
    resources          jsonb       NOT NULL,
    resources_omitted  bigint      NOT NULL CHECK (resources_omitted >= 0),

    state              text        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'completed', 'not_performed', 'unknown')),
    -- How the state was established: by the call that reserved it, by reconciliation, or by a
    -- named person in a resolution record.
    established_by     text        NOT NULL DEFAULT 'call'
        CHECK (established_by IN ('call', 'reconciliation', 'person')),
    established_person text,
    -- The vendor's reference for what was made, once known.
    reference          text,

    CONSTRAINT receipt_resources_known CHECK (
        jsonb_typeof(resources) = 'array'
        OR resources = '"unknown"'::jsonb
        OR coalesce(
            jsonb_typeof(resources) = 'object'
            AND resources - 'reach' = '{}'::jsonb
            AND jsonb_typeof(resources -> 'reach') = 'string'
            AND resources ->> 'reach' <> '',
            false
        )
    ),
    -- None of unknown resources or of a reach is left out.
    CONSTRAINT receipt_resources_shape CHECK (
        jsonb_typeof(resources) = 'array' OR resources_omitted = 0
    ),
    -- A person is named exactly when a person established the state.
    CONSTRAINT established_shape CHECK (
        (established_by = 'person') = (established_person IS NOT NULL)
    )
);

-- A key is unique in its scope: the principal alone when no delegation scope is recorded, and
-- the principal and the delegation's scope otherwise. Two partial indexes rather than one, so
-- that a key with no delegation scope is unique too, which one index would not make it on a
-- server before version 15. Of two calls reserving one key in one scope at once, the second
-- waits for the first and then finds the key taken.
CREATE UNIQUE INDEX receipts_key_in_principal
    ON switchboard_audit.receipts (principal_issuer, principal_subject, idempotency_key)
    WHERE delegation_scope IS NULL;
CREATE UNIQUE INDEX receipts_key_in_delegation
    ON switchboard_audit.receipts
        (principal_issuer, principal_subject, delegation_scope, idempotency_key)
    WHERE delegation_scope IS NOT NULL;

-- Refuses every move the state table does not allow, exactly as the core's `may_move` says, and
-- every other write but a move, for every role:
--
-- - A receipt is reserved `pending`, by its call, with no reference. Its time of reservation is
--   the database's.
-- - It leaves `pending` once, for any of the other three. The call that reserved it may move it
--   so only while its row's deadline has not passed.
-- - It leaves `unknown`, or a `pending` past its row's deadline, only by reconciliation or a
--   person, and only for `completed` or `not_performed`.
-- - Nothing returns to `pending`, and `completed` and `not_performed` are final.
-- - A move writes the state, how it was established, the person and the reference, and nothing
--   else.
--
-- "Past the deadline" is judged by the database's clock at the time of the write: the row's
-- deadline is earlier than clock_timestamp(). So a finish that arrives after the deadline
-- completes its row and leaves its receipt `pending`. A move by the call refused only because
-- the deadline has passed carries the SQLSTATE SB001, which the store reads as that.
CREATE FUNCTION switchboard_audit.receipt_moves() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $receipt_moves$
DECLARE
    past boolean;
    allowed boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'pending' OR NEW.established_by IS DISTINCT FROM 'call'
            OR NEW.established_person IS NOT NULL OR NEW.reference IS NOT NULL THEN
            RAISE EXCEPTION 'receipt % is reserved pending, by its call, with no reference',
                NEW.row_id;
        END IF;
        NEW.reserved_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF to_jsonb(NEW) - ARRAY['state', 'established_by', 'established_person', 'reference']
        IS DISTINCT FROM
       to_jsonb(OLD) - ARRAY['state', 'established_by', 'established_person', 'reference'] THEN
        RAISE EXCEPTION 'only the state of receipt %, how it was established and its reference may be written',
            OLD.row_id;
    END IF;
    -- A row with no deadline counts as past it, so the call cannot move its receipt.
    SELECT c.deadline < clock_timestamp() INTO past
        FROM switchboard_audit.call_rows c WHERE c.id = OLD.row_id;
    past := coalesce(past, true);
    allowed := CASE
        WHEN OLD.state = 'pending' AND NEW.established_by = 'call'
            THEN NOT past AND NEW.state <> 'pending'
        WHEN OLD.state = 'pending'
            THEN past AND NEW.state IN ('completed', 'not_performed')
        WHEN OLD.state = 'unknown' AND NEW.established_by = 'call'
            THEN false
        WHEN OLD.state = 'unknown'
            THEN NEW.state IN ('completed', 'not_performed')
        ELSE false
    END;
    IF allowed IS NOT TRUE THEN
        IF OLD.state = 'pending' AND NEW.established_by = 'call' AND past THEN
            RAISE EXCEPTION 'receipt % is past its row''s deadline, so only reconciliation or a person may move it',
                OLD.row_id USING ERRCODE = 'SB001';
        END IF;
        RAISE EXCEPTION 'receipt % may not move from % to %, established by %',
            OLD.row_id, OLD.state, NEW.state, NEW.established_by;
    END IF;
    RETURN NEW;
END
$receipt_moves$;

REVOKE ALL ON FUNCTION switchboard_audit.receipt_moves() FROM PUBLIC;

CREATE TRIGGER receipt_moves
    BEFORE INSERT OR UPDATE ON switchboard_audit.receipts
    FOR EACH ROW EXECUTE FUNCTION switchboard_audit.receipt_moves();

-- The outcomes `unknown` and `duplicate`. The column check 0001 gave `outcome` allows only `ok`,
-- `error` and `refused`, so it is replaced. A `duplicate` names the earlier receipt it was
-- answered from, and nothing else does.
ALTER TABLE switchboard_audit.call_rows
    DROP CONSTRAINT call_rows_outcome_check;

ALTER TABLE switchboard_audit.call_rows
    ADD COLUMN duplicate_of uuid REFERENCES switchboard_audit.receipts (row_id);

-- Rows written before this migration hold `ok`, `error`, `refused` or no outcome, and no
-- duplicate, so each check holds for them as it is added.
ALTER TABLE switchboard_audit.call_rows
    ADD CONSTRAINT outcome_known CHECK (outcome IN (
        'ok', 'error', 'refused', 'unknown', 'duplicate'
    )),
    -- Each side is true or false, never NULL, so a missing value fails the check.
    ADD CONSTRAINT duplicate_shape CHECK (
        coalesce(outcome = 'duplicate', false) = (duplicate_of IS NOT NULL)
    ),
    -- Nothing ran for a duplicate.
    ADD CONSTRAINT duplicate_latency CHECK (outcome <> 'duplicate' OR latency_ms = 0);

-- What the gateway's role may do with receipts. It reserves one, without its state, how it was
-- established or its time, which the defaults and the trigger give it. It reads them all, for
-- the reuse check, a retried begin and the count of receipts in `unknown`. It moves one through
-- the state, how it was established, the person and the reference only. It cannot delete one.
REVOKE ALL ON switchboard_audit.receipts FROM PUBLIC;
GRANT INSERT (
    row_id, principal_issuer, principal_subject, delegation_scope, idempotency_key, tool,
    tool_use_id, digest, resources, resources_omitted
) ON switchboard_audit.receipts TO switchboard_gateway;
GRANT SELECT (
    row_id, reserved_at, principal_issuer, principal_subject, delegation_scope,
    idempotency_key, tool, tool_use_id, digest, resources, resources_omitted, state,
    established_by, established_person, reference
) ON switchboard_audit.receipts TO switchboard_gateway;
GRANT UPDATE (state, established_by, established_person, reference)
    ON switchboard_audit.receipts TO switchboard_gateway;

-- A reused key's row is written complete at begin, in one insert: `refused` with its sentence,
-- or `duplicate` naming the earlier receipt, each with a latency of zero. set_times gives it
-- its completion time, the same as its time at begin. The role reads back which receipt a
-- duplicate named, so a retried begin can answer what its row was written with.
GRANT INSERT (outcome, outcome_sentence, latency_ms, duplicate_of)
    ON switchboard_audit.call_rows TO switchboard_gateway;
GRANT SELECT (duplicate_of) ON switchboard_audit.call_rows TO switchboard_gateway;
