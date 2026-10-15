-- What decision 0012 adds to a call's row (#22, #56): the pod the caller's token proves, what
-- identifies the verified delegation the call carried, which check a delegation that did not
-- verify failed, and what the control plane answered when asked whether the call's turn is
-- current.
--
-- A verified delegation is recorded by its digest, the SHA-256 of it as presented, its issuer,
-- the key it verified under, the session, turn and execution it was issued for, the epoch of
-- the control plane that issued it, and its egress setting when it carries one. The issuer,
-- key, session, turn and execution are escaped and capped by the core. Its team and person stay
-- in proved_delegation_team and claimed_acting_person.
--
-- A delegation that did not verify is recorded by the check it failed, on the row that check 3
-- denied, and, only when its signature verified and a binding then failed (the audience, the
-- lifetime or the pod), by its digest. Nothing from its claims: decision 0012's later text, the
-- digest after a verified signature, is the one exception to decision 0009's rule that such a
-- row holds nothing from the delegation.
--
-- Additive: no column or row 0001 to 0009 made is changed. Rows written before this migration
-- record none of these: on those rows NULL means not recorded, and each check below holds for
-- them as it is added.
--
-- 0001 to 0009 are not edited: applied versions are recorded, and an edit to one would not
-- apply.

ALTER TABLE switchboard_audit.call_rows
    -- The UID of the pod a workload's token proves, when it names one.
    ADD COLUMN proved_pod           text,
    -- The verified delegation, or the digest of one whose signature verified.
    ADD COLUMN delegation_digest    text,
    ADD COLUMN delegation_issuer    text,
    ADD COLUMN delegation_key_id    text,
    ADD COLUMN delegation_session   text,
    ADD COLUMN delegation_turn      text,
    ADD COLUMN delegation_execution text,
    ADD COLUMN delegation_epoch     bigint,
    ADD COLUMN delegation_egress    text,
    -- Which check a delegation that did not verify failed.
    ADD COLUMN delegation_failure   text,
    -- What the control plane answered when asked whether the call's turn is current.
    ADD COLUMN currency             text;

ALTER TABLE switchboard_audit.call_rows
    -- A pod UID is a UUID in the lowercase hyphenated form, of a workload only.
    ADD CONSTRAINT proved_pod_shape CHECK (
        proved_pod IS NULL
        OR (proved_kind = 'workload'
            AND proved_pod ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    ),
    ADD CONSTRAINT delegation_digest_known CHECK (delegation_digest ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT delegation_epoch_known CHECK (delegation_epoch >= 0),
    ADD CONSTRAINT delegation_egress_known CHECK (delegation_egress IN ('sealed', 'open')),
    ADD CONSTRAINT delegation_failure_known CHECK (delegation_failure IN (
        'version', 'unknown_key', 'retired_key', 'encoding', 'signature', 'malformed',
        'expired', 'not_yet_valid', 'lifetime_over_ceiling', 'wrong_audience', 'wrong_pod'
    )),
    ADD CONSTRAINT currency_known CHECK (currency IN (
        'current', 'superseded', 'ended', 'revoked', 'unconfirmed'
    )),
    -- A verified delegation's columns are written together, with its digest, its team and its
    -- person, or none of them are. An egress setting is one of them, and may be absent. Each
    -- term is true or false, never NULL. Rows written before this migration may hold a team
    -- and a person with none of the rest, so that part is one way only.
    ADD CONSTRAINT delegation_shape CHECK (
        (delegation_issuer IS NULL) = (delegation_key_id IS NULL)
        AND (delegation_issuer IS NULL) = (delegation_session IS NULL)
        AND (delegation_issuer IS NULL) = (delegation_turn IS NULL)
        AND (delegation_issuer IS NULL) = (delegation_execution IS NULL)
        AND (delegation_issuer IS NULL) = (delegation_epoch IS NULL)
        AND (delegation_issuer IS NULL
            OR (delegation_digest IS NOT NULL AND proved_delegation_team IS NOT NULL
                AND claimed_acting_person IS NOT NULL))
        AND (delegation_egress IS NULL OR delegation_issuer IS NOT NULL)
    ),
    -- A failure is recorded exactly on a row check 3 denied for a delegation that did not
    -- verify: a call row, denied, with that reason. A list row has no reason, and so no
    -- failure. Each side is true or false, never NULL.
    ADD CONSTRAINT delegation_failure_shape CHECK (
        coalesce(reason = 'delegation_unverified', false) = (delegation_failure IS NOT NULL)
        AND (delegation_failure IS NULL OR (kind = 'call' AND decision = 'deny'))
    ),
    -- A row that records a failure holds nothing from the delegation's claims: no team, no
    -- person, and none of a verified delegation's columns.
    ADD CONSTRAINT delegation_failure_unclaimed CHECK (
        delegation_failure IS NULL
        OR (proved_delegation_team IS NULL AND claimed_acting_person IS NULL
            AND delegation_issuer IS NULL AND delegation_key_id IS NULL
            AND delegation_session IS NULL AND delegation_turn IS NULL
            AND delegation_execution IS NULL AND delegation_epoch IS NULL
            AND delegation_egress IS NULL)
    ),
    -- A digest belongs to a verified delegation, or to a failure that follows a verified
    -- signature: the audience, the lifetime or the pod. Never to one found before it.
    ADD CONSTRAINT delegation_digest_shape CHECK (
        delegation_digest IS NULL
        OR delegation_issuer IS NOT NULL
        OR coalesce(delegation_failure IN (
            'expired', 'not_yet_valid', 'lifetime_over_ceiling', 'wrong_audience', 'wrong_pod'
        ), false)
    ),
    -- A currency answer is asked for a call, never for a listing.
    ADD CONSTRAINT currency_shape CHECK (currency IS NULL OR kind = 'call');

-- The gateway's role writes them at begin, and a list row's pod and verified delegation. It
-- does not read them back: a repeated begin compares the decision and nothing more.
GRANT INSERT (
    proved_pod, delegation_digest, delegation_issuer, delegation_key_id, delegation_session,
    delegation_turn, delegation_execution, delegation_epoch, delegation_egress,
    delegation_failure, currency
) ON switchboard_audit.call_rows TO switchboard_gateway;
