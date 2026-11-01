-- The gateway's receipts are read by the vendor reference they recorded (decision 0011, section
-- 6; #12). A connector that changes something existing, such as `github__amend_change` amending
-- a draft pull request, first checks that the gateway made it for the same principal: a
-- `completed` receipt of the tool that makes it, for the caller's issuer and subject, in the
-- same vendor target, with the same reference, such as `pull/7`. `github__propose_change` makes
-- the same read when a call's branch already has a pull request.
--
-- An index for that read, over the receipts that recorded a reference. Most receipts never do:
-- a refusal, an error, an `unknown` and an answer that made nothing record none. So the index
-- is partial, and costs nothing for those.
--
-- Additive: no column, row or grant 0008 to 0013 made is changed. The gateway's role already
-- reads every column the query names.
--
-- 0001 to 0013 are not edited: applied versions are recorded, and an edit to one would not
-- apply.

CREATE INDEX receipts_by_reference
    ON switchboard_audit.receipts (reference, tool, target_identifier)
    WHERE reference IS NOT NULL;
