-- The gateway chooses each row's identifier, a UUIDv7, before begin (decision 0009, "Row
-- identifiers"). The database no longer assigns one, and the gateway's role may write it.
--
-- Begin inserts with ON CONFLICT (id) DO NOTHING, so a retried begin writes no second row. It
-- then reads the stored row's decision, which the gateway's role may already select.
--
-- 0001 is not edited: applied versions are recorded, and an edit to one would not apply.

-- A row without an identifier from the gateway cannot be written.
ALTER TABLE switchboard_audit.call_rows ALTER COLUMN id DROP DEFAULT;

-- The identifier, and nothing more, joins the columns the gateway's role inserts.
GRANT INSERT (id) ON switchboard_audit.call_rows TO switchboard_gateway;
