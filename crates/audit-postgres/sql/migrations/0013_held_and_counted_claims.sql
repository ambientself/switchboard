-- Two changes to reconciliation's use of a receipt (decision 0009, "Reconciliation"; #217, #206).
--
-- - A receipt's lease may be written while it is `pending`, whatever its row's deadline, as
--   well as while it reads as `unknown`. The call that reserved a receipt holds its lease while
--   a side effect it answered `unknown` at its deadline runs on in a task of its own, so that no
--   instance looks the receipt up while that call may still act. The hold is written before the
--   call is answered, while the receipt is still `pending` within its row's deadline. A hand-off
--   is still written only while the receipt reads as `unknown`.
-- - Each claim of a receipt is counted, in `claims`, in the claim's own write. Reconciliation
--   counts an attempt when it claims, so a lookup whose record then fails to save still uses up
--   an attempt, and a receipt is looked up a bounded number of times however often saves fail.
--
-- Additive: no column or row 0008 to 0012 made is changed, but for `receipt_moves`, which is
-- replaced. A receipt reserved before this migration has made no counted claim: its lookups so
-- far are its attempts so far.
--
-- 0001 to 0012 are not edited: applied versions are recorded, and an edit to one would not
-- apply.

ALTER TABLE switchboard_audit.receipts
    -- How many times reconciliation has claimed the receipt. Raised by one in each claim.
    ADD COLUMN claims integer NOT NULL DEFAULT 0 CHECK (claims >= 0);

-- receipt_moves, as 0009 made it, and:
--
-- - A receipt is reserved with no claim counted.
-- - Its lease may be written while it is `pending` or `unknown`, as read or not, and has not
--   been handed to a person: never once it is settled or handed off.
-- - Its hand-off and its count of claims may be written only while it reads as `unknown` and
--   has not been handed to a person. A hand-off is recorded once, with the database's time,
--   and never undone. The count of claims only ever rises by one.
-- - A write of the lease, the hand-off or the count of claims that changes neither the state,
--   how it was established, the person nor the reference is not a move, and is judged by the
--   rules above alone. Any other write is judged as a move, as 0009 judged it.
CREATE OR REPLACE FUNCTION switchboard_audit.receipt_moves() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $receipt_moves$
DECLARE
    past boolean;
    allowed boolean;
    unknown boolean;
    leased boolean;
    handed boolean;
    counted boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'pending' OR NEW.established_by IS DISTINCT FROM 'call'
            OR NEW.established_person IS NOT NULL OR NEW.reference IS NOT NULL THEN
            RAISE EXCEPTION 'receipt % is reserved pending, by its call, with no reference',
                NEW.row_id;
        END IF;
        IF NEW.lease_holder IS NOT NULL OR NEW.lease_until IS NOT NULL
            OR NEW.handed_to_person_at IS NOT NULL OR NEW.claims IS DISTINCT FROM 0 THEN
            RAISE EXCEPTION 'receipt % is reserved with no lease, no claim and not handed to a person',
                NEW.row_id;
        END IF;
        NEW.reserved_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF to_jsonb(NEW) - ARRAY['state', 'established_by', 'established_person', 'reference',
                             'lease_holder', 'lease_until', 'handed_to_person_at', 'claims']
        IS DISTINCT FROM
       to_jsonb(OLD) - ARRAY['state', 'established_by', 'established_person', 'reference',
                             'lease_holder', 'lease_until', 'handed_to_person_at', 'claims'] THEN
        RAISE EXCEPTION 'only the state of receipt %, how it was established, its reference, its lease, its hand-off and its claims may be written',
            OLD.row_id;
    END IF;
    -- A row with no deadline counts as past it, so the call cannot move its receipt.
    SELECT c.deadline < clock_timestamp() INTO past
        FROM switchboard_audit.call_rows c WHERE c.id = OLD.row_id;
    past := coalesce(past, true);
    unknown := OLD.state = 'unknown' OR (OLD.state = 'pending' AND past);
    leased := (NEW.lease_holder, NEW.lease_until)
        IS DISTINCT FROM (OLD.lease_holder, OLD.lease_until);
    handed := NEW.handed_to_person_at IS DISTINCT FROM OLD.handed_to_person_at;
    counted := NEW.claims IS DISTINCT FROM OLD.claims;

    IF leased AND (OLD.state NOT IN ('pending', 'unknown')
                   OR OLD.handed_to_person_at IS NOT NULL) THEN
        RAISE EXCEPTION 'receipt % is settled, or was handed to a person, so its lease is not written',
            OLD.row_id;
    END IF;
    IF (handed OR counted) AND (NOT unknown OR OLD.handed_to_person_at IS NOT NULL) THEN
        RAISE EXCEPTION 'receipt % is not in unknown, or was handed to a person, so its hand-off and claims are not written',
            OLD.row_id;
    END IF;
    IF counted AND NEW.claims IS DISTINCT FROM OLD.claims + 1 THEN
        RAISE EXCEPTION 'a claim of receipt % counts one claim more than %, not %',
            OLD.row_id, OLD.claims, NEW.claims;
    END IF;
    IF handed AND NEW.handed_to_person_at IS NOT NULL THEN
        NEW.handed_to_person_at := clock_timestamp();
    END IF;

    IF (NEW.state, NEW.established_by, NEW.established_person, NEW.reference)
        IS NOT DISTINCT FROM
       (OLD.state, OLD.established_by, OLD.established_person, OLD.reference)
        AND (leased OR handed OR counted) THEN
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

-- The gateway's role reads the count of claims, and raises it in a claim; the trigger
-- receipt_moves says when, and by how much.
GRANT UPDATE (claims) ON switchboard_audit.receipts TO switchboard_gateway;
GRANT SELECT (claims) ON switchboard_audit.receipts TO switchboard_gateway;
