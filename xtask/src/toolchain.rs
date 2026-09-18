//! Locating `nargo` and `bb`, and proving they are the pinned versions.
//!
//! A frozen artifact is a deterministic function of the circuit source, the
//! `nargo` that compiled it and the `bb` that derived its key. Two of those
//! three are not in the repository, so a freeze run on a drifted toolchain
//! quietly mints artifacts nobody else can reproduce, and a check run reports a
//! mismatch that looks like a source change and is not.
//!
//! The pins live once, in `mise.toml`. This module reads them from there rather
//! than duplicating them, and asserts them before any compile — so the failure
//! is "your bb is the wrong version", named, before a minute of work, instead of
//! a key diff at the end.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate a tool via `$ENV`, then `$HOME/<home_rel>`, then `PATH`.
pub fn locate(env_var: &str, home_rel: &str, bin: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env_var) {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p = Path::new(&home).join(home_rel);
        if p.exists() {
            return Some(p);
        }
    }
    which(bin)
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.is_file())
}

/// The `mise.toml` value of `[env] <key>`.
///
/// Deliberately a line scan rather than a TOML parse: this is the only thing
/// xtask reads out of `mise.toml`, and a dependency on a TOML reader here would
/// outweigh the two lines it saves.
fn mise_env(root: &Path, key: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(root.join("mise.toml"))
        .map_err(|e| format!("read mise.toml: {e}"))?;
    text.lines()
        .map(str::trim)
        .find_map(|line| {
            let rest = line.strip_prefix(key)?.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            Some(rest.trim_matches('"').to_string())
        })
        .ok_or_else(|| format!("mise.toml has no `{key} = \"...\"` line"))
}

/// `<bin> --version`, first line, trimmed.
fn tool_version(bin: &Path) -> Result<String, String> {
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.lines().next().unwrap_or_default().trim().to_string())
}

/// Locate both tools and assert their versions equal the `mise.toml` pins.
///
/// Runs once, before any compile. Returns `(nargo, bb)`.
pub fn assert_pinned(root: &Path) -> Result<(PathBuf, PathBuf), String> {
    let nargo = locate("NARGO", ".nargo/bin/nargo", "nargo")
        .ok_or("nargo not found (set $NARGO, or `mise run install:noir`)")?;
    let bb =
        locate("BB", ".bb/bb", "bb").ok_or("bb not found (set $BB, or `mise run install:bb`)")?;

    // `nargo --version` prints a multi-field line; `bb --version` prints the
    // bare version. Both only need to *contain* the pin.
    for (label, bin, key) in [("nargo", &nargo, "NOIR_VERSION"), ("bb", &bb, "BB_VERSION")] {
        let want = mise_env(root, key)?;
        let got = tool_version(bin)?;
        if !got.contains(&want) {
            return Err(format!(
                "{label} is {got:?}, but mise.toml pins {key} = {want:?}\n  \
                 using {}\n  \
                 a freeze with the wrong toolchain mints artifacts that will not reproduce",
                bin.display()
            ));
        }
    }
    Ok((nargo, bb))
}
