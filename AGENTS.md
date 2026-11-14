# Working in this repo

## Gates — all clean before every commit

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`cargo test` starts a `postgres:18-alpine` testcontainer, named `messenger-sync-test-pg`
and marked for reuse, so a run attaches to the one the last run left rather than
starting a second. `docker rm -f messenger-sync-test-pg` reclaims it. Tests that need it
skip with a printed reason when Docker is unreachable, so run the suite where Docker
works (on the Windows workstation that is WSL). **Never point tests at
`homelab-postgres`**: nothing in the test support reads a DSN from the environment.

## Commits

- Two lines maximum. No co-author trailers. No emojis.
- Subject line says what changed; the second line says why, if it is not obvious.

## Deployment

Agents build and push images. A human deploys in Dockge unless they explicitly ask
for the deploy to be done for them; when telling the user to deploy, say **Update**
(which pulls the new image), never Restart.

`.github/workflows/tag.yml` and `image.yml` can build a tagged release on GitHub and push it to
ghcr, as the-act-of-complexio does, but they are disabled: images are built by hand on the NAS
and pushed to the local registry. `ci.yml` (fmt, clippy, test, release build) runs on every
pull request.

`/homelab_stack/*` is the live stack and is **read-only to agents**. The host path is
not `/homelab_stack` either — the daemon runs on the host, so a bind of that path
fails. Write stack files through a throwaway container bound to the real path:

    docker run --rm -i -u 0 -v /mnt/.ix-apps/app_mounts/dockge/stacks:/w alpine:3 \
      sh -c 'cat > /w/<stack>/compose.yaml' < deploy/compose.yaml

and bring a stack up with the socket mounted:

    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
      -v /mnt/.ix-apps/app_mounts/dockge/stacks/<stack>:/w -w /w \
      docker:27-cli sh -c "docker compose -p <stack> up -d --pull always"

**This agent's filesystem is not the Docker host's.** `docker run -v $PWD/...` binds
a path that does not exist on the host; Docker answers a missing bind source by
silently creating an empty directory, so the mount "succeeds" and the container sees
nothing. To get local files into a container, build an image (the build context is
sent) or use a named volume and `docker cp`.

**There is no `tank` pool on this machine.** The mounted pools are `quick` and
`archive` (plus `.ix-apps`); `/mnt/tank` is an empty directory on the boot pool. Every
stack keeps its data under `/mnt/quick/apps/volumes/<stack>/`. Because Docker creates a
missing bind source, a wrong pool deploys "successfully". Before trusting a bind path:

    grep " zfs " /proc/mounts | awk '{print $2}'

## Secrets

- `.env` files committed to this repo carry variable **names with empty values**.
- The DSN is a `Secret` (`crates/core/src/config.rs`) whose `Debug` is redacted, so a
  stray log line cannot print it. The client logs counts only, never a message, a name
  or an id.
- The login (cookies) and the encrypted device live in the database's private schemas
  (`client`, `device`), readable only by the ingest role.

## Invariants worth not breaking

- **The MCP binary never links `messenger-client`** (nor `whatsapp-client`): the process
  that serves the archive holds neither the login nor the device keys and cannot reach
  Meta. The root package carrying `src/bin/messenger-mcp.rs` depends on `messenger-core`
  and `messenger-mcp` only, and `tests/archive/isolation.rs` keeps the manifests honest.
  The client is AGPL-3.0 (ported from mautrix-meta and whatsmeow); the rest is MIT.
- **All SQL lives in `crates/core/src/store/`.** Nothing else writes a query;
  `isolation.rs` asserts the tools layer holds none. Two exceptions, because the MCP
  binary links core and must not hold the code that reads a credential: the login
  (`client.session`, the cookie jar) is read and written by
  `crates/client/src/session.rs`, and the encrypted device (`client.device` and the
  `device` schema, whatsapp-client's store) by `crates/client/src/device.rs`.
- **Queries are runtime-checked `sqlx::query*`**, never the `query_as!` macros: those
  want `DATABASE_URL` at build time or a committed `.sqlx/` cache, and the Docker build
  has to stay hermetic. No caller value is ever interpolated into SQL.
- **Migrations are forward-only and never edited once applied.** They are embedded with
  `include_str!` (`crates/core/src/db.rs`); `messenger-client` applies them at boot and
  the MCP only checks they are present.
- **Nothing sends.** The inbox loops issue read tasks only (`145`/`trq` and
  `228`/`mrq.<thread_key>`); any other task label is a write of some kind, and nothing
  in the code enforces that, so review does. The encrypted chat is receive-only: no
  message, no read receipt, no presence — only what any device must send (keepalives,
  acks, `inactive` delivery receipts).
- **A real capture never enters the repository.** A dump of decoded instructions holds
  real people's messages in plaintext; never commit real names, messages or ids. Tests
  use the captured *shapes* with the content replaced.
- **A destructive reset needs a reason.** The device keys and the session are the
  account's encrypted identity; deleting them means re-adopting a device by hand.

## The ones specific to Messenger

**Sync groups are not a detail.** `sync_group: 1` is the regular inbox; `sync_group: 95`
is the end-to-end-encrypted store. A task built for the wrong group returns nothing at
all, silently, which is why every row records its group.

**Group 95 carries no text over LightSpeed.** `upsertMessage` arrives with `[9]`, the null
sentinel, in the text slot. Since 2026-11-14 the text comes from the encrypted chat
instead, decrypted by the adopted device and joined to its envelope by OTID
(`store::e2ee`). Envelopes stored before then stay textless: they render as
`[text not captured]`, never as empty messages, and full-text search can never find
them — a search that misses them looks exactly like one that found everything.

The `dom_capture` / `dom_message` tables hold text the retired browser harvester read off
the rendered page. Those lines carry no message id and are never joined to `message`:
aligning them by order would be guessing, and a wrong guess files one person's sentence
under another person's message. Nothing writes those tables any more.

Raw ops are stored verbatim in `message.raw` and `thread.raw`. When Meta reshapes an op
we reparse history instead of re-fetching it, and a parse failure is loud rather than a
silently missing message.

## Decoding LightSpeed instructions — read positionally, guard on a constant

Every instruction is `[5, "<opName>", <arg>, …]`, and i64s are boxed as
`[19, "<digits>"]` because they exceed 2^53. **Never parse a payload that carries one
through a float** — the preloader's 20-digit `version` rounds, and Meta answers a
rounded version with *no conversations at all* rather than an error.

Decode by **position, with a width check and a marker check**, not by pattern.
Pattern-matching has produced a wrong answer every single time it has been tried:

- "the last short plain string is the title" filed `messenger_reply_reminder` as a
  conversation name.
- "the first plain string that is not a URL is the name" filed
  `/messaging/lightspeed/media_fallback/?entity_id=…` as a person's name for **every
  one of 175 contacts** — a *relative* URL contains no `http`, so the filter missed it.

The guard is what makes positional reading safe: if the constant is not where it
should be, or the width is wrong, **refuse the instruction** rather than decode it
into the wrong columns. Verify a shape across *every* captured instance, not the one
you eyeballed — the roster's marker looked like it was at `[8]` from one sample and is
actually at `[11]`, which checking all 247 caught.

### Shapes established from live captures

| instruction | n | width | key positions |
| --- | --- | --- | --- |
| `upsertMessage` | 158 | 84 | text 2, thread 5, ts 7, id 10, sender 12, **reply-to 25**, quoted text 30 |
| `deleteThenInsertThread` | — | 92 | updated 2, preview 4, **title 5**, marker 8 = `80`, key 9 |
| `addParticipantIdToGroupThread` | 247 | 17 | thread 2, user 3, joined 4, label 9, **marker 11 = `80`**, admin 15 |
| `upsertReaction` | 35 | 9 | thread 2, **message 4**, actor 5, emoji 6, marker 7 = `80`, ts 8 |
| `insertBlobAttachment` | 2 | 51 | id 2, url 5, mime 8, preview 10, thread 29, **message 34** |
| `insertXmaAttachment` | 12 | 135 | url 10, mime 13, thread 27, **message 32** |
| `verifyContactRowExists` | 293 | 25 | id 2, picture 4, **name 5**, no handle |
| `deleteThenInsertContact` | 175 | 61 | id 2, picture 4, **name 11, handle 12** |

**Media and reactions do not travel inside the message.** A photo or GIF arrives as
its own `insertBlobAttachment`, a link preview as `insertXmaAttachment`, a reaction as
`upsertReaction` — each naming the message it belongs to. This is why a media message
decodes with no text at all, and why it must not render identically to an empty one.

**The roster is delivered for DMs too**, despite `…GroupThread` in the name. A DM has
`title IS NULL` by construction, so membership is the only way to name one.

## Crawl control — what "the end" actually looks like

**Never terminate history on "no rows written".** That is also what a settle window
expiring early, a shed event, and a task built for the wrong sync group all look like —
and `history_done` is a one-way door nothing clears on its own. Key off messages
**decoded**, and require an empty page to repeat (`history_empty_pages_to_finish`,
default 2) before setting the flag. `store::writes::reopen_history` exists because a
wrong completion has to be recoverable.

**Backward paging is not enough.** A finished thread is never re-selected by the
history walk, so without a forward walk the archive fills once and goes stale.
`thread.newest_seen_at` versus the listing's `last_activity_at` is how a thread
announces it has moved. Forward runs before backward: a day that runs out of budget
should have spent it staying current.

## Method — the rules this project keeps re-learning

- **A page is not a total.** "16 threads" and "52 threads" were both reported as
  inbox totals and both were single pages. Say which one you have.
- **Verify a decoder against every captured instance**, not one sample.
- **Check the primary source before reporting a fix.** A grants migration was written
  to close a gap the provisioning script had already closed with
  `ALTER DEFAULT PRIVILEGES`; reading it first would have saved the migration.
