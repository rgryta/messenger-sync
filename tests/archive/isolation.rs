//! The credential-isolation guard.
//!
//! The MCP process holds neither the login nor the device keys and must not be able to
//! reach Meta, and in Cargo that is a link-time fact: the binary's package does not depend
//! on `messenger-client`, so the code that could use them is not in the process at all.
//!
//! What is left to check is that the manifests still say so, and that the tools layer
//! still holds no SQL of its own. Both are the invariants `AGENTS.md` names.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn manifest(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// One manifest section, ending where the next one starts.
///
/// `[dependencies]` is what reaches a binary target; `[dev-dependencies]` does not, and
/// reading to the end of the file would conflate the two.
fn section(path: &str, name: &str) -> String {
    let manifest = manifest(path);
    let after = manifest
        .split_once(&format!("\n[{name}]"))
        .unwrap_or_else(|| panic!("{path} has no [{name}] section"))
        .1;
    after
        .split_once("\n[")
        .map_or(after, |(section, _)| section)
        .to_owned()
}

#[test]
fn the_mcp_binary_does_not_link_the_client() {
    // The root package is the one that carries `src/bin/messenger-mcp.rs`.
    let dependencies = section("Cargo.toml", "dependencies");
    // `messenger-client` holds the login and the device keys, and is AGPL besides, as is the
    // `whatsapp-client` it builds on: the MIT binary links none of them.
    for crate_name in ["messenger-client", "whatsapp-client"] {
        assert!(
            !dependencies.contains(crate_name),
            "the MCP binary must not link {crate_name}:\n{dependencies}"
        );
    }
}

#[test]
fn neither_the_core_nor_the_mcp_crate_depends_on_the_client() {
    // A transitive edge would put the code back in the binary just as surely.
    for path in ["crates/core/Cargo.toml", "crates/mcp/Cargo.toml"] {
        for crate_name in ["messenger-client", "whatsapp-client"] {
            assert!(
                !manifest(path).contains(crate_name),
                "{path} must not depend on {crate_name}"
            );
        }
    }
}

#[test]
fn the_tools_layer_holds_no_sql_of_its_own() {
    // `AGENTS.md`: all SQL lives in the store. `set-alias` is the only write in the whole
    // read surface, and `0003_grant_mcp_role.sql` grants the role nothing else.
    for file in ["crates/mcp/src/tools.rs", "crates/mcp/src/server.rs"] {
        let source = std::fs::read_to_string(repo_root().join(file))
            .expect(file)
            .to_lowercase();
        for statement in ["insert into", "update ", "delete from", "select "] {
            assert!(!source.contains(statement), "raw {statement:?} in {file}");
        }
    }
}
