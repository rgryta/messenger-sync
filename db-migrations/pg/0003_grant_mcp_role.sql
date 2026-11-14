-- Give the read-only role exactly the write authority it needs, and nothing else.
--
-- `ALTER DEFAULT PRIVILEGES` in the provisioning script grants SELECT on every table
-- the harvester creates, which covers reading the archive. It does not cover the two
-- alias tables, which the MCP server writes — those hold names the operator chose for
-- their own people and Messenger never sees them.
--
-- Without this, `set-alias` fails at runtime with "permission denied for table
-- person_alias" and nothing else does, so the gap looks like a bug in one tool rather
-- than a missing grant.
--
-- Guarded on the role existing: every test container is a host where it does not, and
-- a migration that only works on the production box is a migration that gets skipped
-- in tests and then surprises somebody.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'messenger_mcp') THEN
    RAISE NOTICE 'messenger_mcp absent; skipping the grants that belong to it';
    RETURN;
  END IF;

  GRANT SELECT ON ALL TABLES IN SCHEMA public TO messenger_mcp;
  GRANT INSERT, UPDATE, DELETE ON person_alias, person_alias_member TO messenger_mcp;
END $$;
