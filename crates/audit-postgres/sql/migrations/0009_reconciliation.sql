-- Reconciliation of `unknown` receipts (decision 0009, part 2, "Reconciliation"). A receipt
-- gains the vendor target a lookup looks in, taken at begin from the call's resources as its
-- tool's settlement says; a short lease, which one gateway instance claims it with before any
-- lookup is made; and when it was handed to a person. Each lookup made is a row of
-- `receipt_lookups`, appended and never changed or removed.
--
-- Additive: no column or row 0008 made is changed. A receipt reserved before this migration
-- has no target, no lease, no lookups and was handed to no one, so it goes to a person once
-- reconciliation finds it in `unknown`.
--
-- 0001 to 0008 are not edited: applied versions are recorded, and an edit to one would not
-- apply.

ALTER TABLE switchboard_audit.receipts
    -- Where a lookup looks for the effect: one resource the call named, of the system and kind
    -- its tool's settlement declares. Empty for a tool settled by a person.
    ADD COLUMN target_system       text,
    ADD COLUMN target_kind         text,
    ADD COLUMN target_identifier   text,
    -- Who holds the lease, and until when, by the database's clock. A lease is free once its
    -- time has passed.
    ADD COLUMN lease_holder        text,
    ADD COLUMN lease_until         timestamptz,
    -- When the receipt was handed to a person, by the database's clock. It stays `unknown`.
    ADD COLUMN handed_to_person_at timestamptz,
    -- A target is all three columns or none.
    ADD CONSTRAINT target_shape CHECK (
        (target_system IS NULL) = (target_kind IS NULL)
        AND (target_kind IS NULL) = (target_identifier IS NULL)
    ),
    -- A lease has a holder and an end, or neither.
    ADD CONSTRAINT lease_shape CHECK ((lease_holder IS NULL) = (lease_until IS NULL));

-- The lookups made. One row per attempt, numbered from 1 for each receipt.
CREATE TABLE switchboard_audit.receipt_lookups (
    row_id        uuid        NOT NULL REFERENCES switchboard_audit.receipts (row_id),
    attempt       integer     NOT NULL CHECK (attempt >= 1),
    -- The database's time at the insert, set by the trigger lookup_appends for every role.
    looked_up_at  timestamptz NOT NULL,
    result        text        NOT NULL CHECK (result IN ('found', 'not_found', 'failed')),
    -- Whether the vendor documents the search as complete and current.
    authoritative boolean     NOT NULL,
    -- The vendor's reference for what a found effect made.
    reference     text,
    PRIMARY KEY (row_id, attempt),
    -- A found effect has a reference and is authoritative; nothing else has a reference; a
    -- failed lookup is not authoritative.
    CONSTRAINT lookup_shape CHECK (
        (result = 'found') = (reference IS NOT NULL)
        AND (result <> 'found' OR authoritative)
        AND (result <> 'failed' OR NOT authoritative)
    )
);

-- A lookup is appended to a receipt that reads as `unknown` and has not been handed to a
-- person, as the next attempt, with the database's time. It is never changed or removed, by
-- any role.
CREATE FUNCTION switchboard_audit.lookup_appends() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $lookup_appends$
DECLARE
    open boolean;
    made integer;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'a lookup of receipt % is never changed or removed', OLD.row_id;
    END IF;
    SELECT (r.state = 'unknown' OR (r.state = 'pending' AND c.deadline < clock_timestamp()))
               AND r.handed_to_person_at IS NULL
        INTO open
        FROM switchboard_audit.receipts r
            JOIN switchboard_audit.call_rows c ON c.id = r.row_id
        WHERE r.row_id = NEW.row_id;
    IF open IS NOT TRUE THEN
        RAISE EXCEPTION 'receipt % is not in unknown, or was handed to a person, so no lookup is recorded on it',
            NEW.row_id;
    END IF;
    SELECT count(*) INTO made FROM switchboard_audit.receipt_lookups l
        WHERE l.row_id = NEW.row_id;
    IF NEW.attempt IS DISTINCT FROM made + 1 THEN
        RAISE EXCEPTION 'receipt % has % lookups, so the next is attempt %, not %',
            NEW.row_id, made, made + 1, NEW.attempt;
    END IF;
    NEW.looked_up_at := clock_timestamp();
    RETURN NEW;
END
$lookup_appends$;

REVOKE ALL ON FUNCTION switchboard_audit.lookup_appends() FROM PUBLIC;

CREATE TRIGGER lookup_appends
    BEFORE INSERT OR UPDATE OR DELETE ON switchboard_audit.receipt_lookups
    FOR EACH ROW EXECUTE FUNCTION switchboard_audit.lookup_appends();

-- receipt_moves, as 0008 made it, and:
--
-- - A receipt is reserved with no lease and not handed to anyone.
-- - Its lease and its hand-off may be written, and nothing else beside a move, only while it
--   reads as `unknown` and has not been handed to a person. A hand-off is recorded once, with
--   the database's time, and never undone.
-- - Reconciliation settles a receipt only on a lookup recorded on it that establishes the
--   state: `completed`, with the reference of a lookup that found the effect, or
--   `not_performed`, on a search that found nothing and was authoritative. Not once the
--   receipt has been handed to a person.
-- - A write of the lease or the hand-off that changes neither the state, how it was
--   established, the person nor the reference is not a move, and is judged by the rules above
--   alone. Any other write is judged as a move, as 0008 judged every one.
CREATE OR REPLACE FUNCTION switchboard_audit.receipt_moves() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $receipt_moves$
DECLARE
    past boolean;
    allowed boolean;
    unknown boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'pending' OR NEW.established_by IS DISTINCT FROM 'call'
            OR NEW.established_person IS NOT NULL OR NEW.reference IS NOT NULL THEN
            RAISE EXCEPTION 'receipt % is reserved pending, by its call, with no reference',
                NEW.row_id;
        END IF;
        IF NEW.lease_holder IS NOT NULL OR NEW.lease_until IS NOT NULL
            OR NEW.handed_to_person_at IS NOT NULL THEN
            RAISE EXCEPTION 'receipt % is reserved with no lease and not handed to a person',
                NEW.row_id;
        END IF;
        NEW.reserved_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF to_jsonb(NEW) - ARRAY['state', 'established_by', 'established_person', 'reference',
                             'lease_holder', 'lease_until', 'handed_to_person_at']
        IS DISTINCT FROM
       to_jsonb(OLD) - ARRAY['state', 'established_by', 'established_person', 'reference',
                             'lease_holder', 'lease_until', 'handed_to_person_at'] THEN
        RAISE EXCEPTION 'only the state of receipt %, how it was established, its reference, its lease and its hand-off may be written',
            OLD.row_id;
    END IF;
    -- A row with no deadline counts as past it, so the call cannot move its receipt.
    SELECT c.deadline < clock_timestamp() INTO past
        FROM switchboard_audit.call_rows c WHERE c.id = OLD.row_id;
    past := coalesce(past, true);
    unknown := OLD.state = 'unknown' OR (OLD.state = 'pending' AND past);

    IF (NEW.lease_holder, NEW.lease_until, NEW.handed_to_person_at)
        IS DISTINCT FROM (OLD.lease_holder, OLD.lease_until, OLD.handed_to_person_at) THEN
        IF NOT unknown OR OLD.handed_to_person_at IS NOT NULL THEN
            RAISE EXCEPTION 'receipt % is not in unknown, or was handed to a person, so its lease and hand-off are not written',
                OLD.row_id;
        END IF;
        IF NEW.handed_to_person_at IS NOT NULL THEN
            NEW.handed_to_person_at := clock_timestamp();
        END IF;
    END IF;

    IF (NEW.state, NEW.established_by, NEW.established_person, NEW.reference)
        IS NOT DISTINCT FROM
       (OLD.state, OLD.established_by, OLD.established_person, OLD.reference)
        AND (NEW.lease_holder, NEW.lease_until, NEW.handed_to_person_at)
        IS DISTINCT FROM (OLD.lease_holder, OLD.lease_until, OLD.handed_to_person_at) THEN
        RETURN NEW;
    END IF;

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
    IF NEW.established_by = 'reconciliation' THEN
        IF OLD.handed_to_person_at IS NOT NULL THEN
            RAISE EXCEPTION 'receipt % was handed to a person, so reconciliation no longer settles it',
                OLD.row_id;
        END IF;
        IF NOT EXISTS (
            SELECT FROM switchboard_audit.receipt_lookups l
            WHERE l.row_id = OLD.row_id
                AND ((NEW.state = 'completed' AND l.result = 'found'
                      AND l.reference IS NOT DISTINCT FROM NEW.reference)
                     OR (NEW.state = 'not_performed' AND l.result = 'not_found'
                         AND l.authoritative))
        ) THEN
            RAISE EXCEPTION 'receipt % is settled % by reconciliation only on a lookup recorded on it that establishes it',
                OLD.row_id, NEW.state;
        END IF;
    END IF;
    RETURN NEW;
END
$receipt_moves$;

-- What the gateway's role may do for reconciliation. It reserves a receipt with its target,
-- reads every column of it, and writes its lease and its hand-off; the trigger receipt_moves
-- says when. It appends a lookup, without its time, which the trigger lookup_appends gives
-- it, and reads the lookups. It cannot change or delete a lookup, nor delete a receipt.
GRANT INSERT (target_system, target_kind, target_identifier)
    ON switchboard_audit.receipts TO switchboard_gateway;
GRANT SELECT (
    target_system, target_kind, target_identifier, lease_holder, lease_until,
    handed_to_person_at
) ON switchboard_audit.receipts TO switchboard_gateway;
GRANT UPDATE (lease_holder, lease_until, handed_to_person_at)
    ON switchboard_audit.receipts TO switchboard_gateway;

REVOKE ALL ON switchboard_audit.receipt_lookups FROM PUBLIC;
GRANT INSERT (row_id, attempt, result, authoritative, reference)
    ON switchboard_audit.receipt_lookups TO switchboard_gateway;
GRANT SELECT (row_id, attempt, looked_up_at, result, authoritative, reference)
    ON switchboard_audit.receipt_lookups TO switchboard_gateway;
