//! `cargo xtask` — canonical-circuit release tooling.
//!
//! `freeze-circuits` is the **only** step that runs `nargo`/`bb`. It compiles
//! the head noir sources under `crates/pso-zk-canonical/noir/` and, for each
//! circuit whose ACIR changed, mints a new frozen version under
//! `crates/pso-zk-canonical/resources/circuits/<module>/<version>/` and records
//! it (status `active`) in `circuits/manifest.toml`.
//!
//! When a new version supersedes the previously-active one, the old entry is set
//! to `deprecated`, its `circuit_hash` is written into the manifest (preserving
//! its identity), and its `bytecode.b64` + `abi.json` are deleted — keeping only
//! `circuit.vk`, since verification needs only the VK (a retired prover ships its
//! own bytecode).
//!
//! Version bump: an unchanged ACIR is skipped; a changed ACIR with the same ABI
//! is a patch bump; an ABI change requires `--abi-change` (minor) or `--semantic`
//! (major) so the layout/DOMAIN decision is explicit. `cargo build` never runs
//! this — it reads the frozen artifacts read-only.
//!
//! `freeze-circuits --check` is the dry run CI gates on. It does the same
//! compile and the same key derivation, against a scratch copy of the whole
//! `noir/` tree under `target/`, and asserts every committed `active` artifact
//! reproduces byte for byte. It writes nothing outside `target/`, reports every
//! failing module rather than stopping at the first, and exits 1 if any differ.
//! Without it nothing proves the committed verifying keys still come from the
//! committed sources.

// `xtask` is a CLI binary; stdout/stderr is its interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod scratch;
mod toolchain;

use base64::Engine;
use tiny_keccak::{Hasher, Keccak};
use toml_edit::{value, DocumentMut, Table};

/// The noir bin circuits: (package dir under `noir/`, nargo package name).
/// `noir/` also holds `pso-circuit-core`, a shared library package, which is
/// not listed here because it produces no ACIR of its own.
const CIRCUITS: &[(&str, &str)] = &[
    ("pso-ownership-circuit", "ownership_proof"),
    ("pso-flat-aggregation-circuit-n1", "flat_aggregation_n1"),
    ("pso-flat-aggregation-circuit-n2", "flat_aggregation_n2"),
    ("pso-flat-aggregation-circuit-n4", "flat_aggregation_n4"),
    ("pso-flat-aggregation-circuit-n8", "flat_aggregation_n8"),
    ("pso-flat-aggregation-circuit-n16", "flat_aggregation_n16"),
    ("pso-flat-aggregation-circuit-n32", "flat_aggregation_n32"),
    ("pso-flat-aggregation-circuit-n64", "flat_aggregation_n64"),
    ("pso-full-circuit", "full_proof"),
];

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("freeze-circuits") => freeze(&args.collect::<Vec<_>>()),
        other => {
            eprintln!("unknown command {other:?}");
            eprintln!("usage: cargo xtask freeze-circuits [--abi-change | --semantic]");
            std::process::exit(2);
        }
    }
}

fn freeze(flags: &[String]) {
    // Reject what we do not understand. `any(|f| f == ...)` silently ignores
    // an unknown flag, so `freeze-circuits --check` — a plausible thing to
    // type, and a command the sibling outbe-circuits repo really has — used to
    // run a REAL freeze: needs nargo and bb, and rewrites manifest.toml and
    // mints a version if any ACIR moved. There is no dry-run mode here; a
    // typo must not silently become a write.
    if let Some(unknown) = flags
        .iter()
        .find(|f| !matches!(f.as_str(), "--semantic" | "--abi-change" | "--check"))
    {
        eprintln!("unknown flag {unknown:?}");
        eprintln!("usage: cargo xtask freeze-circuits [--check | --abi-change | --semantic]");
        std::process::exit(2);
    }
    let check = flags.iter().any(|f| f == "--check");
    let semantic = flags.iter().any(|f| f == "--semantic");
    let abi_change = flags.iter().any(|f| f == "--abi-change");
    if check && (semantic || abi_change) {
        eprintln!("--check is a dry run and mints nothing, so a bump flag with it is a mistake");
        std::process::exit(2);
    }

    let root = workspace_root();
    // `crates/`, not the repo root: the canonical crate moved under it and this
    // path did not follow, so every freeze command panicked on a missing
    // manifest. Nothing caught it because no CI job runs xtask.
    let canonical = root.join("crates").join("pso-zk-canonical");
    let noir = canonical.join("noir");
    let resources = canonical.join("resources/circuits");
    let manifest_path = canonical.join("circuits/manifest.toml");

    // Before any compile: the artifacts are a function of these two binaries as
    // much as of the sources, so a drift here is not a source change and should
    // not be reported as one.
    let (nargo, bb) = match toolchain::assert_pinned(&root) {
        Ok(pair) => pair,
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    };

    if check {
        check_circuits(&noir, &resources, &manifest_path, &root, &nargo, &bb);
        return;
    }

    let mut doc: DocumentMut = std::fs::read_to_string(&manifest_path)
        .expect("read manifest.toml")
        .parse()
        .expect("parse manifest.toml");

    let mut minted = 0usize;
    for (dir, module) in CIRCUITS {
        let pkg = noir.join(dir);
        let st = Command::new(&nargo)
            .arg("compile")
            .current_dir(&pkg)
            .status()
            .unwrap_or_else(|e| panic!("spawn nargo for {dir}: {e}"));
        assert!(st.success(), "nargo compile failed for {dir}");

        let json_path = pkg.join("target").join(format!("{module}.json"));
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).expect("read circuit json"))
                .expect("parse circuit json");
        let bytecode = json["bytecode"].as_str().expect("bytecode").to_string();
        let abi_str = serde_json::to_string(&json["abi"]).expect("serialize abi");
        let acir = base64::engine::general_purpose::STANDARD
            .decode(&bytecode)
            .expect("base64");
        let new_hash = keccak_hex(&acir);

        // The module's current active version, if any.
        let aot = doc["circuit"]
            .as_array_of_tables()
            .expect("[[circuit]] array");
        let active = (0..aot.len()).find_map(|i| {
            let t = aot.get(i).unwrap();
            (t["module"].as_str() == Some(*module) && t["status"].as_str() == Some("active"))
                .then(|| (i, t["version"].as_str().unwrap().to_string()))
        });

        let (new_version, supersede) = match &active {
            Some((idx, ver)) => {
                let dir_v = resources.join(module).join(ver);
                let cur_b64 =
                    std::fs::read_to_string(dir_v.join("bytecode.b64")).expect("active bytecode");
                let cur_acir = base64::engine::general_purpose::STANDARD
                    .decode(cur_b64.trim())
                    .expect("active base64");
                let cur_hash = keccak_hex(&cur_acir);
                if cur_hash == new_hash {
                    println!("  unchanged  {module} @ {ver}");
                    continue;
                }
                // Semantic ABI compare (structural, key-order/format-insensitive)
                // — a raw-string compare would false-positive on serializer
                // differences (jq vs serde_json).
                let cur_abi: Option<serde_json::Value> =
                    std::fs::read_to_string(dir_v.join("abi.json"))
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok());
                let abi_differs = cur_abi.as_ref() != Some(&json["abi"]);
                let nv = if abi_differs {
                    if semantic {
                        bump(ver, 0)
                    } else if abi_change {
                        bump(ver, 1)
                    } else {
                        panic!("{module}: ABI changed — pass --abi-change (minor) or --semantic (major)");
                    }
                } else {
                    bump(ver, 2)
                };
                (nv, Some((*idx, ver.clone(), cur_hash)))
            }
            None => ("1.0.0".to_string(), None),
        };

        write_version(
            &resources,
            module,
            &new_version,
            &bytecode,
            &abi_str,
            &bb,
            &json_path,
        );

        // Append the new active entry (bytecode present -> build.rs derives the hash).
        let mut t = Table::new();
        t["module"] = value(*module);
        t["label"] = value(label(module));
        t["version"] = value(new_version.clone());
        t["status"] = value("active");
        doc["circuit"].as_array_of_tables_mut().unwrap().push(t);

        match supersede {
            Some((idx, ver, hash)) => {
                // Deprecate the old version + preserve its identity. The artifact
                // drop happens in the reconcile pass below.
                let old = doc["circuit"]
                    .as_array_of_tables_mut()
                    .unwrap()
                    .get_mut(idx)
                    .unwrap();
                old["status"] = value("deprecated");
                old["circuit_hash"] = value(hash);
                println!("  minted     {module} {ver} -> {new_version}  (old -> deprecated)");
            }
            None => println!("  minted     {module} @ {new_version}  (new)"),
        }
        minted += 1;
    }

    reconcile_artifacts(&mut doc, &resources);

    std::fs::write(&manifest_path, doc.to_string()).expect("write manifest.toml");
    println!("\n{minted} circuit(s) minted.");
}

/// Enforce the on-disk artifacts of every entry to match its status (idempotent;
/// also applies to statuses hand-edited into the manifest):
///   * `active`     — bytecode + abi + vk (kept);
///   * `deprecated` — vk only (bytecode + abi dropped; still verifies);
///   * `revoked`    — nothing (vk dropped too; the version dir removed).
///
/// Before deleting anything it preserves the binary identity in the manifest
/// (`circuit_hash`) if not already recorded — covering a direct active→revoked
/// edit where the bytecode is still present.
fn reconcile_artifacts(doc: &mut DocumentMut, resources: &Path) {
    let n = doc["circuit"].as_array_of_tables().unwrap().len();
    for i in 0..n {
        let (module, version, status, has_hash) = {
            let t = doc["circuit"].as_array_of_tables().unwrap().get(i).unwrap();
            (
                t["module"].as_str().unwrap().to_string(),
                t["version"].as_str().unwrap().to_string(),
                t["status"].as_str().unwrap().to_string(),
                t.get("circuit_hash").is_some(),
            )
        };
        if status == "active" {
            continue;
        }
        let dir = resources.join(&module).join(&version);

        if !has_hash {
            if let Ok(b64) = std::fs::read_to_string(dir.join("bytecode.b64")) {
                if let Ok(acir) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                    let hash = keccak_hex(&acir);
                    doc["circuit"]
                        .as_array_of_tables_mut()
                        .unwrap()
                        .get_mut(i)
                        .unwrap()["circuit_hash"] = value(hash);
                }
            }
        }

        let _ = std::fs::remove_file(dir.join("bytecode.b64"));
        let _ = std::fs::remove_file(dir.join("abi.json"));
        if status == "revoked" {
            let _ = std::fs::remove_file(dir.join("circuit.vk"));
            let _ = std::fs::remove_dir(&dir); // succeeds only if now empty
        }
    }
}

/// Write a frozen version dir: `bytecode.b64`, `abi.json`, and `circuit.vk`
/// (derived via `bb write_vk -t evm-no-zk`).
fn write_version(
    resources: &Path,
    module: &str,
    version: &str,
    bytecode_b64: &str,
    abi_str: &str,
    bb: &Path,
    json_path: &Path,
) {
    let dir = resources.join(module).join(version);
    std::fs::create_dir_all(&dir).expect("mkdir version dir");
    std::fs::write(dir.join("bytecode.b64"), bytecode_b64).expect("write bytecode.b64");
    std::fs::write(dir.join("abi.json"), abi_str).expect("write abi.json");

    let tmp = dir.join(".bb");
    std::fs::create_dir_all(&tmp).expect("mkdir bb tmp");
    let st = Command::new(bb)
        .arg("write_vk")
        .arg("-b")
        .arg(json_path)
        .arg("-o")
        .arg(&tmp)
        .args(["-t", "evm-no-zk"])
        .status()
        .unwrap_or_else(|e| panic!("spawn bb for {module}: {e}"));
    assert!(st.success(), "bb write_vk failed for {module}");
    let produced = tmp.join("vk");
    assert!(produced.exists(), "bb produced no vk for {module}");
    std::fs::rename(&produced, dir.join("circuit.vk")).expect("install circuit.vk");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// keccak256 -> lower-case hex (no `0x`).
fn keccak_hex(bytes: &[u8]) -> String {
    let mut h = Keccak::v256();
    h.update(bytes);
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bump a `"a.b.c"` semver: level 0 = major, 1 = minor, 2 = patch.
fn bump(ver: &str, level: u8) -> String {
    let mut p: Vec<u64> = ver.split('.').map(|x| x.parse().unwrap_or(0)).collect();
    while p.len() < 3 {
        p.push(0);
    }
    match level {
        0 => {
            p[0] += 1;
            p[1] = 0;
            p[2] = 0;
        }
        1 => {
            p[1] += 1;
            p[2] = 0;
        }
        _ => p[2] += 1,
    }
    format!("{}.{}.{}", p[0], p[1], p[2])
}

/// Canonical dotted label for a module.
fn label(module: &str) -> String {
    match module {
        "ownership_proof" => "pso.ownership".to_string(),
        "full_proof" => "pso.full_proof".to_string(),
        m => {
            let n = m
                .strip_prefix("flat_aggregation_n")
                .expect("unknown module");
            format!("pso.flat_aggregation.n{n}")
        }
    }
}

/// Workspace root = the xtask crate's parent directory.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn check_circuits(
    noir: &Path,
    resources: &Path,
    manifest_path: &Path,
    root: &Path,
    nargo: &Path,
    bb: &Path,
) {
    let doc: DocumentMut = std::fs::read_to_string(manifest_path)
        .expect("read manifest.toml")
        .parse()
        .expect("parse manifest.toml");
    let entries = doc["circuit"]
        .as_array_of_tables()
        .expect("[[circuit]] array");

    // Compile the copy, never the tree. `nargo compile` writes `target/` beside
    // the sources, which on the real tree would dirty the checkout that CI then
    // asserts is clean.
    let scratch = scratch::Scratch::copy_of(noir, &root.join("target"), "freeze-check")
        .unwrap_or_else(|e| panic!("{e}"));

    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (dir, module) in CIRCUITS {
        let Some(version) = (0..entries.len()).find_map(|i| {
            let t = entries.get(i).unwrap();
            (t["module"].as_str() == Some(*module) && t["status"].as_str() == Some("active"))
                .then(|| t["version"].as_str().unwrap().to_string())
        }) else {
            // No active entry: nothing is committed to reproduce. A circuit
            // that exists only as source is not yet part of the contract.
            println!("  skipped    {module}  (no active version)");
            continue;
        };

        let pkg = scratch.path().join(dir);
        let st = Command::new(nargo)
            .arg("compile")
            .current_dir(&pkg)
            .status()
            .unwrap_or_else(|e| panic!("spawn nargo for {dir}: {e}"));
        if !st.success() {
            failures.push(format!("{module}: nargo compile failed"));
            continue;
        }

        let json_path = pkg.join("target").join(format!("{module}.json"));
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).expect("read circuit json"))
                .expect("parse circuit json");
        let bytecode = json["bytecode"].as_str().expect("bytecode");

        let committed = resources.join(module).join(&version);
        let mut module_failed = false;

        // 1. ACIR. Compared by keccak of the decoded bytes, which is the
        //    identity the chain matches on, not by the base64 spelling.
        let acir = base64::engine::general_purpose::STANDARD
            .decode(bytecode)
            .expect("base64");
        let want_b64 = std::fs::read_to_string(committed.join("bytecode.b64"))
            .expect("committed bytecode.b64");
        let want_acir = base64::engine::general_purpose::STANDARD
            .decode(want_b64.trim())
            .expect("committed base64");
        if keccak_hex(&acir) != keccak_hex(&want_acir) {
            failures.push(format!(
                "{module} @ {version}: ACIR differs (committed {}, compiled {})",
                keccak_hex(&want_acir),
                keccak_hex(&acir)
            ));
            module_failed = true;
        }

        // 2. ABI, structurally. A string compare false-positives on serializer
        //    differences that change no meaning.
        let want_abi: Option<serde_json::Value> =
            std::fs::read_to_string(committed.join("abi.json"))
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok());
        if want_abi.as_ref() != Some(&json["abi"]) {
            failures.push(format!("{module} @ {version}: ABI differs"));
            module_failed = true;
        }

        // 3. The verifying key. Derived into the scratch tree, never beside the
        //    committed artifact. This is the one a verifier actually loads, so
        //    a match on ACIR alone is not enough — it would miss a bb change.
        let vk_out = pkg.join(".bb-check");
        std::fs::create_dir_all(&vk_out).expect("mkdir vk scratch");
        let st = Command::new(bb)
            .arg("write_vk")
            .arg("-b")
            .arg(&json_path)
            .arg("-o")
            .arg(&vk_out)
            .args(["-t", "evm-no-zk"])
            .status()
            .unwrap_or_else(|e| panic!("spawn bb for {module}: {e}"));
        if !st.success() {
            failures.push(format!("{module}: bb write_vk failed"));
            continue;
        }
        let produced = std::fs::read(vk_out.join("vk")).expect("read derived vk");
        let want_vk = std::fs::read(committed.join("circuit.vk")).expect("committed circuit.vk");
        if produced != want_vk {
            failures.push(format!(
                "{module} @ {version}: circuit.vk differs ({} vs {} bytes)",
                want_vk.len(),
                produced.len()
            ));
            module_failed = true;
        }

        checked += 1;
        if !module_failed {
            println!("  reproduces {module} @ {version}");
        }
    }

    if failures.is_empty() {
        println!("\n{checked} circuit(s) reproduce from their committed sources.");
        return;
    }
    eprintln!("\n{} circuit(s) did NOT reproduce:", failures.len());
    for f in &failures {
        eprintln!("  {f}");
    }
    eprintln!(
        "\nEither the sources moved without a freeze (run `cargo xtask freeze-circuits`),\n\
         or the toolchain is not the one that produced the committed artifacts."
    );
    std::process::exit(1);
}
