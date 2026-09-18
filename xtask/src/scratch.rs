//! A copied tree that deletes itself.
//!
//! The dry run must not write into the repository, and `nargo compile` insists
//! on writing `<package>/target/` next to the sources it compiles. So the check
//! copies the whole `noir/` tree under `target/` and compiles the copy.
//!
//! The copy has to disappear even when the run fails, and a check run fails by
//! design — that is its job. A `Drop` guard rather than a cleanup call at the
//! end, because the interesting paths out of a check are the early returns and
//! the panics, and those are exactly the ones a trailing cleanup misses.

use std::path::{Path, PathBuf};

/// A directory removed when this value is dropped, including on unwind.
pub struct Scratch(pub PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        // Best effort: a failure to clean up must not mask the real error that
        // is already propagating.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Scratch {
    /// Copy `src` to a fresh scratch directory and return the guard.
    ///
    /// The path carries the process id so two runs cannot collide, which also
    /// means a leftover from a killed run never gets reused.
    pub fn copy_of(src: &Path, under: &Path, tag: &str) -> Result<Self, String> {
        let dest = under.join(format!("xtask-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        let guard = Scratch(dest);
        copy_tree(src, &guard.0).map_err(|e| format!("copy {} -> scratch: {e}", src.display()))?;
        Ok(guard)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Recursive copy, skipping any `target/` directory.
///
/// Skipping `target/` keeps the copy small and, more importantly, stops a stale
/// build artifact from a previous local compile being copied in and mistaken
/// for a fresh one.
fn copy_tree(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        let from = entry.path();
        let to = dest.join(&name);
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}
