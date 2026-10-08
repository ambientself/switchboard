-- One row per call that reaches a decision, denials included (design section 11).
--
-- Applied by `migrate`, as switchboard_owner, inside the schema switchboard_audit, which
-- `migrate` creates. The columns follow `gateway_core::AuditRecord`. Proved and claimed values
-- are separate columns. The two times are set by the database's clock, never by the gateway:
-- by the trigger set_times at insert and complete_once at completion.

CREATE TABLE switchboard_audit.call_rows (
    -- Assigned by the database when the row is begun.
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The database's time at begin, and at completion. The gateway's role cannot write either,
    -- and the triggers overwrite whatever any other role writes.
    begun_at               timestamptz NOT NULL,
    finished_at            timestamptz,

    tool_use_id            text,
    deployment             text        NOT NULL,
    surface                text        NOT NULL,
    profile                text        NOT NULL,
    tool                   text        NOT NULL,
    connector              text,
    classification         text
        CHECK (classification IN ('read', 'propose', 'write', 'destructive')),
    -- The resources the call named: a JSON array of {system, kind, identifier}, each value
    -- escaped and capped by the core, or the JSON string "unknown" when the tool could not
    -- say before it ran.
    resources              jsonb       NOT NULL
        CHECK (jsonb_typeof(resources) = 'array' OR resources = '"unknown"'::jsonb),
    -- How many distinct named resources were left out of `resources`. None can be left out
    -- of resources nobody could name.
    resources_omitted      bigint      NOT NULL CHECK (resources_omitted >= 0),
    decision               text        NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason                 text,
    sentence               text,
    policy_revision        text        NOT NULL,

    -- The caller, as proved: issuer and subject, and either a workload's team or a user's
    -- groups.
    proved_issuer          text        NOT NULL,
    proved_subject         text        NOT NULL,
    proved_kind            text        NOT NULL CHECK (proved_kind IN ('workload', 'user')),
    proved_team            text,
    proved_groups          text[],
    -- The team a delegation was issued for, which its signature proves.
    proved_delegation_team text,
    -- Stated, not proved: the person a delegation names, and a team the caller stated.
    claimed_acting_person  text,
    claimed_team           text,

    -- The completion, written once by finish. Empty on a denial, and on an allowed call
    -- whose outcome the gateway never learned.
    outcome                text        CHECK (outcome IN ('ok', 'error', 'refused')),
    outcome_sentence       text,
    latency_ms             bigint      CHECK (latency_ms >= 0),

    CONSTRAINT resources_shape CHECK (
        resources <> '"unknown"'::jsonb OR resources_omitted = 0
    ),
    CONSTRAINT proved_kind_shape CHECK (
        (proved_kind = 'workload') = (proved_team IS NOT NULL)
        AND (proved_kind = 'user') = (proved_groups IS NOT NULL)
    ),
    -- A denial has a reason and a sentence and is never completed. An allowed call was
    -- served by a connector, under a classification.
    CONSTRAINT decision_shape CHECK (
        CASE decision
            WHEN 'deny' THEN reason IS NOT NULL AND sentence IS NOT NULL AND outcome IS NULL
            ELSE reason IS NULL AND sentence IS NULL
                AND connector IS NOT NULL AND classification IS NOT NULL
        END
    ),
    -- The completion columns are written together, and only a refusal carries a sentence.
    CONSTRAINT completion_shape CHECK (
        (outcome IS NULL) = (latency_ms IS NULL)
        AND (outcome IS NULL) = (finished_at IS NULL)
        AND coalesce(outcome = 'refused', false) = (outcome_sentence IS NOT NULL)
    )
);

-- Completes a row at most once, and writes nothing else. Grants already stop the gateway's
-- role writing any other column; this holds for every role, the owner included, so "at most
-- once" is a property of the table and not only of the code that writes to it.
CREATE FUNCTION switchboard_audit.complete_once() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $complete_once$
BEGIN
    IF OLD.decision <> 'allow' THEN
        RAISE EXCEPTION 'audit row % records a denial, which is never completed', OLD.id;
    END IF;
    IF OLD.outcome IS NOT NULL THEN
        RAISE EXCEPTION 'audit row % is already complete', OLD.id;
    END IF;
    IF NEW.outcome IS NULL THEN
        RAISE EXCEPTION 'a completion of audit row % has no outcome', OLD.id;
    END IF;
    IF to_jsonb(NEW) - ARRAY['outcome', 'outcome_sentence', 'latency_ms', 'finished_at']
        IS DISTINCT FROM
       to_jsonb(OLD) - ARRAY['outcome', 'outcome_sentence', 'latency_ms', 'finished_at'] THEN
        RAISE EXCEPTION 'only the completion of audit row % may be written', OLD.id;
    END IF;
    NEW.finished_at := clock_timestamp();
    RETURN NEW;
END
$complete_once$;

REVOKE ALL ON FUNCTION switchboard_audit.complete_once() FROM PUBLIC;

CREATE TRIGGER complete_once
    BEFORE UPDATE ON switchboard_audit.call_rows
    FOR EACH ROW EXECUTE FUNCTION switchboard_audit.complete_once();

-- Sets both times from the database's clock at insert, overwriting anything the insert
-- carried, for every role. A row is begun now. A row written complete at insert, which only
-- the owner can write, is complete at the same moment.
CREATE FUNCTION switchboard_audit.set_times() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $set_times$
BEGIN
    NEW.begun_at := clock_timestamp();
    NEW.finished_at := CASE WHEN NEW.outcome IS NULL THEN NULL ELSE NEW.begun_at END;
    RETURN NEW;
END
$set_times$;

REVOKE ALL ON FUNCTION switchboard_audit.set_times() FROM PUBLIC;

CREATE TRIGGER set_times
    BEFORE INSERT ON switchboard_audit.call_rows
    FOR EACH ROW EXECUTE FUNCTION switchboard_audit.set_times();

-- What the gateway's role may do. It inserts the first half of a row, without the identifier
-- or the times. It completes a row through the completion columns only. It reads back only
-- what finish needs: which row, whether it was allowed, and its completion. It cannot read who
-- called what, and it cannot delete.
REVOKE ALL ON switchboard_audit.call_rows FROM PUBLIC;
GRANT USAGE ON SCHEMA switchboard_audit TO switchboard_gateway;
GRANT INSERT (
    tool_use_id, deployment, surface, profile, tool, connector, classification,
    resources, resources_omitted, decision, reason, sentence, policy_revision,
    proved_issuer, proved_subject, proved_kind, proved_team, proved_groups,
    proved_delegation_team, claimed_acting_person, claimed_team
) ON switchboard_audit.call_rows TO switchboard_gateway;
GRANT UPDATE (outcome, outcome_sentence, latency_ms)
    ON switchboard_audit.call_rows TO switchboard_gateway;
GRANT SELECT (id, decision, outcome, outcome_sentence, latency_ms)
    ON switchboard_audit.call_rows TO switchboard_gateway;
