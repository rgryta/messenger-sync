//! The read surface.
//!
//! This crate must never depend on `messenger-client`: the MCP process holds neither the
//! login nor the device keys and must be unable to reach Meta even by accident. The
//! absence of the dependency edge is what the linker enforces, and
//! `tests/archive/isolation.rs` checks the manifests still say so.

pub mod render;
pub mod server;
pub mod tools;
