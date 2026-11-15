-- The history device enrolled in Messenger's encrypted backup: its storage and mailbox keys
-- and the epoch keys it has derived so far, which together read the account's archived
-- encrypted chats. Kept with the login, out of the MCP role's reach. `device` is
-- `securehistory::Device` as JSON; an empty `id` is an enrolment Meta has not confirmed.
CREATE TABLE client.history_device (
    account_id text PRIMARY KEY,
    device     jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
