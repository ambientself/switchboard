-- The exception that allowed a call (decision 0011, section 9; #12, #56): the name of the
-- exception in the caller's profile that let the call's `write` tool past check 5. It is not a
-- reason, which belongs to a denial, so it has a column of its own.
--
-- The name comes from the gateway's configuration, and the core holds it to 1 to 64 characters
-- of lowercase letters, digits and `-`, not starting or ending with `-`. It is written only on
-- an allowed call row of a `write` or `destructive` tool: never on a denial, a read, a proposal
-- or a list row. The loader lets an exception name only `write` tools; the column takes either
-- side-effecting classification check 5 denies, so that the row's shape and the loader's rule
-- are separate guards.
--
-- Additive: no column or row 0001 to 0011 made is changed. Rows written before this migration
-- record none, and NULL on them means not recorded; each check below holds for them as it is
-- added. The column is not named `exception`, a PL/pgSQL keyword, since the table's triggers
-- are PL/pgSQL.
--
-- 0001 to 0011 are not edited: applied versions are recorded, and an edit to one would not
-- apply.

ALTER TABLE switchboard_audit.call_rows
    ADD COLUMN allowed_by_exception text;

ALTER TABLE switchboard_audit.call_rows
    -- The name's shape, as the core makes it.
    ADD CONSTRAINT allowed_by_exception_known CHECK (
        length(allowed_by_exception) BETWEEN 1 AND 64
        AND allowed_by_exception ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    ),
    -- Recorded only on an allowed call of a tool check 5 denies unless an exception names it.
    -- A list row has no decision or classification, so the test is made true or false, never
    -- NULL, which a check would pass.
    ADD CONSTRAINT allowed_by_exception_shape CHECK (
        allowed_by_exception IS NULL
        OR coalesce(kind = 'call' AND decision = 'allow'
            AND classification IN ('write', 'destructive'), false)
    );

-- The gateway's role writes it at begin. It does not read it back: a repeated begin compares
-- the decision and nothing more.
GRANT INSERT (allowed_by_exception) ON switchboard_audit.call_rows TO switchboard_gateway;
