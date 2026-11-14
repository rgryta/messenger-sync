//! A browser-less Messenger client: Meta's gateway socket, LightSpeed, and the encrypted
//! device, which replaced the Chromium harvester. Ported from mautrix-meta (AGPL-3.0).

pub mod armadillo;
pub mod chat;
pub mod collect;
pub mod cookies;
pub mod daemon;
pub mod device;
pub mod dgw;
pub mod e2ee;
pub mod gateway;
pub mod graphql;
pub mod inbox;
pub mod ls;
pub mod ops;
pub mod page;
pub mod session;
