//! Every SQL statement in the project.
//!
//! No other module writes a query — the invariant `AGENTS.md` names. Functions are
//! plain `async fn` over a `PgPool` rather than methods on a type, so tests can call
//! them directly without constructing a service.
//!
//! Two rules hold throughout. Queries are **runtime-checked** `sqlx::query*`, never the
//! `query_as!` macros: those need a live `DATABASE_URL` at build time or a committed
//! `.sqlx/` cache regenerated on every SQL edit, inside what has to stay a hermetic
//! Docker build — and `tests/archive/store.rs` already runs every query against a real
//! Postgres. And **no caller value is ever interpolated into SQL**: the fragments below
//! are `concat!`-composed `&'static str`, which is also what sqlx's `SqlSafeStr` bound
//! enforces, so a query built from a `String` does not type-check. Where a direction has
//! to vary there are two static constants rather than one formatted query.
//!
//! The read half and the three alias writers are the MCP role's (`0003_grant_mcp_role.sql`
//! grants it no other write). [`writes`] and [`e2ee`] are the client's. The DOM capture's
//! writers were never ported: nothing captures any more.

// The shared SQL fragments, as macros rather than `const`s so the queries below can stay
// `&'static str` through `concat!`. They were ported verbatim from the retired Python's
// module-level constants of the same name, and they are declared above the `mod` statements because
// `macro_rules!` is textually scoped.

/// Rows for things nobody sent, excluded from every count of "messages".
///
/// NOTHING SETS THESE YET, so the exclusion is currently a no-op. It is kept rather than
/// dropped because the classification belongs in one place, and because the shape of the
/// eventual fix is known: Messenger delivers reactions and read receipts as their own
/// instructions, which the decoder does not store at all, so the only rows that could
/// need classifying are admin messages arriving through `upsertMessage`.
macro_rules! is_a_message {
    () => {
        "m.item_type <> ALL ('{action_log,call_event,thread_event}'::text[])"
    };
}

/// A thread whose text arrives no other way: it holds messages, and not one of them
/// carries any.
///
/// This replaced `sync_group = 95`, which named the end-to-end-encrypted store and was
/// the wrong question to ask. Measured on the live archive: 55 threads hold nothing but
/// text-less messages, and only 16 sit in that store. The other 39 are 1:1 DMs in the
/// plain store holding 9,992 rows with no text at all. Keyed on the store they were
/// filed under, those 39 were excluded from capture, counted as ordinary, and rendered
/// as though they had been sent empty.
///
/// `text IS NULL` is the honest test: across all 206,878 stored rows `text` is either
/// present or NULL and never the empty string.
macro_rules! thread_has_no_text {
    () => {
        concat!(
            "
        EXISTS (SELECT 1 FROM message m
                 WHERE m.account_id = t.account_id AND m.thread_key = t.thread_key
                   AND ",
            is_a_message!(),
            ")
   AND NOT EXISTS (SELECT 1 FROM message m
                 WHERE m.account_id = t.account_id AND m.thread_key = t.thread_key
                   AND ",
            is_a_message!(),
            " AND m.text IS NOT NULL)
"
        )
    };
}

/// Whether capture has read any of a thread's words off the client's screen.
///
/// Those lines are text the envelopes never carried, so a thread holding them is no
/// longer "metadata only" however many text-less envelopes sit beside them. The argument
/// is the alias of the table naming the thread: `t` for a thread, `m` for a message.
macro_rules! has_rendered_lines {
    ($row:literal) => {
        concat!(
            "
        EXISTS (SELECT 1 FROM dom_capture rc JOIN dom_message rd ON rd.capture_id = rc.id
                 WHERE rc.account_id = ",
            $row,
            ".account_id AND rc.thread_key = ",
            $row,
            ".thread_key
                   AND rd.ts IS NOT NULL)
    "
        )
    };
}

/// One rendered line, once.
///
/// A capture is a cumulative walk: it starts at the newest screen and merges its way
/// back, so each pass stores everything the one before it stored plus whatever new
/// ground it covered. Three captures of one conversation therefore hold its newest lines
/// three times — measured 700 rows for 445 distinct lines on one thread, and 5,700 rows
/// for 2,815 lines across the archive. Reading or searching an encrypted thread repeated
/// more than half of it.
///
/// Deduped on the line itself rather than by keeping only the newest capture, because a
/// capture is not always a superset: a thread whose history is finished gets the shallow
/// look at its tail, which would hide everything deeper if the newest row set were taken
/// as the whole record.
macro_rules! rendered_lines {
    () => {
        "
        SELECT DISTINCT ON (c.account_id, c.thread_key, d.ts, d.text, d.sender_label)
               c.account_id, c.thread_key, d.ts, d.text, d.sender_label, d.search
          FROM dom_message d
          JOIN dom_capture c ON c.id = d.capture_id
         WHERE d.ts IS NOT NULL
         ORDER BY c.account_id, c.thread_key, d.ts, d.text, d.sender_label,
                  c.captured_at DESC
"
    };
}

/// How many rows the request matched before `LIMIT`, so a truncated answer can say so.
macro_rules! total_matches {
    () => {
        "count(*) OVER () AS total_matches"
    };
}

mod aliases;
pub mod e2ee;
mod messages;
mod people;
mod revisions;
mod status;
mod threads;
pub mod writes;

pub use aliases::{delete_alias, list_aliases, set_alias};
pub use messages::{count_history, get_history, search_messages};
pub use people::{find_people, resolve_people};
pub use revisions::{Deletion, list_revisions, resolve_message};
pub use status::{account_status, sync_loops};
pub use threads::list_threads;
