-- Rows of kind 'list' (decision 0009, "`tools/list` is an audit row of its own kind"). A list
-- row records who asked, on which surface, under which profile and policy revision, and the
-- names of the tools the answer listed: at most 64, each escaped and capped by the core, with
-- the rest counted. It is written complete, has no deadline and no completion, and is never
-- open.
--
-- A list row has no tool, decision or resources, so those columns lose NOT NULL, and the
-- constraint kind_shape says which columns each kind has. decision_shape is rewritten so a row
-- with no decision passes it; resources_shape already does, since a check whose result is NULL
-- passes. complete_once is replaced: its test of the decision was NULL for a row with none, and
-- let the update through.
--
-- 0001 is not edited: applied versions are recorded, and an edit to one would not apply.

ALTER TABLE switchboard_audit.call_rows
    -- The names of the tools listed: a JSON array of strings, in the order listed.
    ADD COLUMN listed_tools   jsonb,
    -- How many tools the answer listed past those named.
    ADD COLUMN listed_omitted bigint,
    ALTER COLUMN tool DROP NOT NULL,
    ALTER COLUMN decision DROP NOT NULL,
    ALTER COLUMN resources DROP NOT NULL,
    ALTER COLUMN resources_omitted DROP NOT NULL,
    DROP CONSTRAINT decision_shape,
    -- A denial has a reason and a sentence and is never completed. An allowed call was
    -- served by a connector, under a classification. A list row has no decision.
    ADD CONSTRAINT decision_shape CHECK (
        CASE decision
            WHEN 'deny' THEN reason IS NOT NULL AND sentence IS NOT NULL AND outcome IS NULL
            WHEN 'allow' THEN reason IS NULL AND sentence IS NULL
                AND connector IS NOT NULL AND classification IS NOT NULL
            ELSE decision IS NULL
        END
    ),
    -- A list row has its tools and their count and none of a call's columns: no tool-use
    -- identifier, tool, connector, classification, resources, decision, reason, sentence,
    -- outcome, allowance or deadline. A call row has no tools listed, and has its tool,
    -- decision and resources. Each term is true or false, never NULL, so a missing value fails
    -- the check rather than passing it.
    ADD CONSTRAINT kind_shape CHECK (
        CASE kind
            WHEN 'list' THEN listed_tools IS NOT NULL AND jsonb_typeof(listed_tools) = 'array'
                AND listed_omitted IS NOT NULL AND listed_omitted >= 0
                AND tool_use_id IS NULL AND tool IS NULL AND connector IS NULL
                AND classification IS NULL AND resources IS NULL AND resources_omitted IS NULL
                AND decision IS NULL AND reason IS NULL AND sentence IS NULL
                AND outcome IS NULL AND allowance_ms IS NULL AND deadline IS NULL
            WHEN 'call' THEN listed_tools IS NULL AND listed_omitted IS NULL
                AND tool IS NOT NULL AND decision IS NOT NULL
                AND resources IS NOT NULL AND resources_omitted IS NOT NULL
        END
    );

-- Completes a call row at most once, and writes nothing else. A list row is written complete
-- and is never completed, and neither is a denial. Both tests are true or false for any row,
-- including one with no decision.
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

-- The gateway's role writes a list row's tools and their count.
GRANT INSERT (listed_tools, listed_omitted) ON switchboard_audit.call_rows TO switchboard_gateway;
