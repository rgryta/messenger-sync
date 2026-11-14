//! One test binary, so one testcontainer is started for the whole suite.
//!
//! Rust has no session-scoped fixture, and a separate `tests/*.rs` file would mean a
//! separate process and a separate Postgres container each. The modules below share one,
//! taking turns through a mutex because they share its database.
//!
//! The module comments name the retired Python test file each was ported from, where
//! there was one.

mod e2ee;
mod isolation;
mod render;
mod schema;
mod server;
mod store;
mod support;
mod tools;
mod writes;
