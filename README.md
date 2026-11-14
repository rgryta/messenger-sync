# messenger-sync

A permanent archive of Facebook Messenger conversations in PostgreSQL, and a
read-only MCP server over it. All Rust.

Messenger has no usable HTTP API, so `messenger-client` talks to Meta the way the web
client does, without a browser: the LightSpeed gateway socket for the inbox, and the
end-to-end-encrypted chat as one of the account's own devices for one-to-one text.

```
messenger-client ──> LightSpeed gateway + encrypted chat ──> PostgreSQL
                                                                │
messenger-mcp ──────────────────────────────────────────────────┘  (read-only)
```

## Layout

| path | what |
| ---- | ---- |
| `crates/client` | `messenger-client`: the inbox loops, the encrypted chat, the login and device (AGPL-3.0, ported from mautrix-meta) |
| `crates/core` | models, the pool, the migrations runner, and every SQL statement (`store/`) |
| `crates/mcp`, `src/bin/messenger-mcp.rs` | the read-only MCP server on `/mcp` |
| `db-migrations/pg` | the archive's schema, applied by `messenger-client` at boot |
| `deploy/` | the image, the compose stack, the role provisioning SQL |

## What it can and cannot reach

Group chats live in Messenger's regular store and are archived with full history,
text included.

One-to-one chats are end-to-end encrypted. Since 2026-11-14 the client is an adopted
device of the account and decrypts their text as it arrives. Envelopes stored before
then carry no text and stay that way; the MCP says so rather than rendering them as
empty messages, and they never match a search.

Nothing here sends, reacts or marks anything read. The inbox loops issue read tasks
only, and the encrypted chat sends only what any device must (keepalives, acks and
`inactive` delivery receipts).

## Running

One image, two services (`deploy/compose.yaml`): `messenger-client` (the only
container with the login, the device keys and DDL rights) and `messenger-mcp` (reads
the archive, nothing else). `.env.example` lists the three variables the stack needs.

See `AGENTS.md` for the rules of working in this repo.
