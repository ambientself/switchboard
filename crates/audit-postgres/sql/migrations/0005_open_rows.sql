-- The open rows (decision 0009, "Open rows"): allowed rows of kind 'call' with no completion
-- past their deadline, judged by the database's clock. A denial is never completed and a list
-- row is written complete, so neither is ever open. A row before its deadline may still be
-- completed, so it is not open yet.
--
-- The view shows which row, its deadline and when it was begun, and nothing about who called
-- or what. It runs with its owner's privileges, so the gateway's role reads it although it
-- cannot read begun_at on the table. The boot check requires this exact definition, owned by
-- switchboard_owner.
--
-- Nothing marks a row abandoned or writes its outcome: decision 0009 rejects that. The query
-- only says which rows are open.

CREATE VIEW switchboard_audit.open_call_rows AS
    SELECT id, deadline, begun_at
    FROM switchboard_audit.call_rows
    WHERE kind = 'call' AND decision = 'allow' AND outcome IS NULL
        AND deadline < clock_timestamp();

-- The gateway's role reads it. A reader role is not one the migrations know: the demo's
-- migrate.sh grants switchboard_reader SELECT on every table and view in the schema, this one
-- included, after migrating.
REVOKE ALL ON switchboard_audit.open_call_rows FROM PUBLIC;
GRANT SELECT ON switchboard_audit.open_call_rows TO switchboard_gateway;
