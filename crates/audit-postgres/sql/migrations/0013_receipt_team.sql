-- A receipt records the proved principal's team at begin (decision 0009, "Reconciliation"; #12).
-- A lookup by marker reads through a credential narrowed to the receipt's team and target, and
-- the team is not otherwise in the receipt: its scope holds the principal's issuer and subject,
-- not the team they were mapped to when the call was made.
--
-- `team` is the workload's team, and NULL for a person, who has none. A receipt reserved
-- before this migration reads NULL: a GitHub lookup of one fails, so it goes to a person once
-- its attempts are used up.
--
-- Additive: no column or row 0008 to 0012 made is changed. The trigger receipt_moves already
-- refuses an update of any column but the state, how it was established, the person, the
-- reference, the lease, the hand-off and the claims, so the team is written once, at the
-- insert.
--
-- 0001 to 0012 are not edited: applied versions are recorded, and an edit to one would not
-- apply.

ALTER TABLE switchboard_audit.receipts
    -- The proved principal's team when the call was begun, or NULL.
    ADD COLUMN team text;

-- The gateway's role writes the team when it reserves a receipt, and reads it back for
-- reconciliation.
GRANT INSERT (team) ON switchboard_audit.receipts TO switchboard_gateway;
GRANT SELECT (team) ON switchboard_audit.receipts TO switchboard_gateway;
