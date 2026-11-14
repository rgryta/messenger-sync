-- The login: Messenger's cookie jar, which is this account to anyone holding it.
--
-- In its own schema, out of the MCP role's reach. `public` is not safe for this: the live
-- database has default privileges granting the MCP role SELECT on every table the ingest
-- role creates there, and the MCP is reachable through MCPHub. A new schema grants nothing
-- to anyone but its owner; the REVOKE says so out loud.
REVOKE ALL ON SCHEMA client FROM PUBLIC;

CREATE TABLE client.session (
    account_id text PRIMARY KEY,
    -- Playwright's cookie array, the shape `cookies::Jar` reads and writes.
    cookies    jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
