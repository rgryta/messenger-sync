-- Provision the `messenger` database and its two roles on homelab-postgres.
--
-- Run as the postgres superuser:
--   psql -h homelab-postgres -U postgres \
--     -v ingest_pw="<ingest password>" -v mcp_pw="<mcp password>" \
--     -f deploy/provision-messenger-db.sql
--
-- NOTE: pass RAW passwords. :'ingest_pw' quotes the value once; pre-quoting stores
-- the literal quotes in the role password and authentication then fails with a
-- message that says nothing about quoting.

CREATE ROLE messenger_ingest LOGIN PASSWORD :'ingest_pw';
CREATE ROLE messenger_mcp    LOGIN PASSWORD :'mcp_pw';

CREATE DATABASE messenger OWNER messenger_ingest;

\connect messenger

GRANT ALL ON SCHEMA public TO messenger_ingest;
GRANT USAGE ON SCHEMA public TO messenger_mcp;

-- Redundant on PostgreSQL 15 and above and harmless there. Kept because the
-- read-only rule is a risk control rather than a preference, and it should not
-- depend on the server version this database happens to be restored onto.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Without CREATE on the tablespaces, the migration that places the corpus fails soft
-- and everything silently stays on the default volume. Guarded because a host without
-- these tablespaces is a valid host.
DO $$ BEGIN
  EXECUTE 'GRANT CREATE ON TABLESPACE archive_data, nvme_indexes TO messenger_ingest';
EXCEPTION WHEN undefined_object THEN
  RAISE NOTICE 'archive_data/nvme_indexes absent; the corpus will live on the default tablespace';
END $$;

-- The MCP role reads everything and writes only the alias tables. This is a grant
-- rather than a convention: "the MCP server cannot alter the archive" is enforced
-- by the database, not by the code above it.
--
-- Default privileges cover the tables the client has yet to create. The tables
-- that already exist, and the alias write authority, are granted by
-- 0003_grant_mcp_role.sql, because at this point there is no schema to grant on.
ALTER DEFAULT PRIVILEGES FOR ROLE messenger_ingest IN SCHEMA public
    GRANT SELECT ON TABLES TO messenger_mcp;
