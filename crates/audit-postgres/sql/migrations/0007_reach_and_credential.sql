-- How a call's resources were found, and the credential identity it runs under (decisions 0011
-- and 0014).
--
-- A tool declared as its connector entry's reach names the entry's whole reach on every call.
-- The row records that reach by reference, as the JSON object {"reach": "<entry>"}, not as a
-- list: a reach can hold more resources than a row keeps, and the row's policy revision says
-- exactly what it was. Nothing of a reach is left out, so its count is zero.
--
-- The credential identity is the configured identity of the tool's connector entry, recorded
-- at begin: the entry's stated credential mode and the vendor-side principal its credential
-- acts as, never the secret. Both are set or neither is. They are NULL on a row whose call
-- names no tool with an entry, and on every row written before this migration, which did not
-- record them: on those rows NULL means not recorded.
--
-- 0001 is not edited: applied versions are recorded, and an edit to one would not apply.

-- The column check 0001 gave `resources`, which allows only an array or "unknown".
ALTER TABLE switchboard_audit.call_rows
    DROP CONSTRAINT call_rows_resources_check;

ALTER TABLE switchboard_audit.call_rows
    ADD COLUMN credential_mode text,
    ADD COLUMN credential_principal text;

ALTER TABLE switchboard_audit.call_rows
    -- An array of named resources, "unknown", or a reach: an object with the one key `reach`,
    -- naming an entry. A list row has no resources, and NULL passes a check. The reach's test
    -- is false, never NULL, for an object without the key, so such an object fails the check.
    ADD CONSTRAINT resources_known CHECK (
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
    -- None of a reach is left out, as none of unknown resources can be.
    ADD CONSTRAINT reach_shape CHECK (
        jsonb_typeof(resources) <> 'object' OR resources_omitted = 0
    ),
    ADD CONSTRAINT credential_mode_known CHECK (credential_mode IN (
        'team_service_identity', 'gateway_token', 'per_user_grant'
    )),
    -- A mode and its principal are written together, or neither is. Each side is true or false,
    -- never NULL.
    ADD CONSTRAINT credential_shape CHECK (
        (credential_mode IS NULL) = (credential_principal IS NULL)
    );

-- The gateway's role writes both at begin. It does not read them back: a repeated begin
-- compares the decision and nothing more.
GRANT INSERT (credential_mode, credential_principal)
    ON switchboard_audit.call_rows TO switchboard_gateway;
