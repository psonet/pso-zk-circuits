#!/usr/bin/env python3
"""Measure the canonical circuits, and diff two measurements.

Circuit size is the cost model: ACIR opcode count drives witness generation,
and `circuit_size` (the backend gate count) drives proving time, memory and
the VK. Both move silently — a helper that looks equivalent can double a
circuit — so this measures them and a PR comment shows the delta.

  collect <noir-dir> -o sizes.json   compile each circuit and record its sizes
  report <base.json> <head.json>     render the comparison as Markdown

`bb gates` is the source of both numbers; `nargo info --json` reports opcodes
alone. The `-t` target matters: gate count depends on it, so this uses the
same `evm-no-zk` the freeze path writes VKs with, and a number measured under
any other target would not describe what ships.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

# (package directory under noir/, nargo package name). Mirrors CIRCUITS in
# xtask/src/main.rs; pso-circuit-core is a library and emits no ACIR.
CIRCUITS = [
    ("pso-ownership-circuit", "ownership_proof"),
    ("pso-flat-aggregation-circuit-n1", "flat_aggregation_n1"),
    ("pso-flat-aggregation-circuit-n2", "flat_aggregation_n2"),
    ("pso-flat-aggregation-circuit-n4", "flat_aggregation_n4"),
    ("pso-flat-aggregation-circuit-n8", "flat_aggregation_n8"),
    ("pso-flat-aggregation-circuit-n16", "flat_aggregation_n16"),
    ("pso-flat-aggregation-circuit-n32", "flat_aggregation_n32"),
    ("pso-flat-aggregation-circuit-n64", "flat_aggregation_n64"),
    ("pso-full-circuit", "full_proof"),
]

# The verifier target the freeze path uses (xtask/src/main.rs).
TARGET = "evm-no-zk"
# Below this, a move is noise from a compiler detail rather than a change
# worth a reviewer's attention.
NOTABLE_PCT = 1.0


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        print(f"$ {' '.join(map(str, cmd))}\n{r.stdout}\n{r.stderr}", file=sys.stderr)
        raise SystemExit(f"command failed: {cmd[0]}")
    return r.stdout


def collect(noir: Path, nargo: str, bb: str) -> dict:
    out = {}
    for pkg_dir, module in CIRCUITS:
        pkg = noir / pkg_dir
        if not pkg.is_dir():
            raise SystemExit(f"missing circuit package: {pkg}")
        run([nargo, "compile"], cwd=pkg)
        artifact = pkg / "target" / f"{module}.json"
        if not artifact.exists():
            raise SystemExit(f"nargo compile produced no {artifact}")
        raw = run([bb, "gates", "-b", str(artifact), "-t", TARGET])
        doc = json.loads(raw)
        fns = doc.get("functions") or []
        if not fns:
            raise SystemExit(f"bb gates returned no functions for {module}: {raw[:200]}")
        # A bin circuit has exactly one entry point; sum defensively so an
        # extra function is counted rather than silently dropped.
        out[module] = {
            "opcodes": sum(f["acir_opcodes"] for f in fns),
            "gates": sum(f["circuit_size"] for f in fns),
        }
        print(f"  {module:24} opcodes={out[module]['opcodes']:>8,}  "
              f"gates={out[module]['gates']:>9,}", file=sys.stderr)
    return out


def delta(before: int | None, after: int | None) -> str:
    if before is None:
        return "new"
    if after is None:
        return "removed"
    d = after - before
    if d == 0:
        return "—"
    pct = (d / before * 100) if before else 0.0
    return f"{d:+,} ({pct:+.2f}%)"


def report(base: dict, head: dict, base_ref: str) -> str:
    modules = sorted(set(base) | set(head))
    rows, moved = [], False
    for m in modules:
        b, h = base.get(m), head.get(m)
        bo, ho = (b or {}).get("opcodes"), (h or {}).get("opcodes")
        bg, hg = (b or {}).get("gates"), (h or {}).get("gates")
        if (bo, bg) != (ho, hg):
            moved = True
        rows.append(
            f"| `{m}` | {ho if ho is not None else '—':,} | {delta(bo, ho)} "
            f"| {hg if hg is not None else '—':,} | {delta(bg, hg)} |"
            if isinstance(ho, int) and isinstance(hg, int) else
            f"| `{m}` | — | {delta(bo, ho)} | — | {delta(bg, hg)} |"
        )

    tb = sum(v["gates"] for v in base.values())
    th = sum(v["gates"] for v in head.values())

    out = ["## Circuit size", ""]
    if not moved:
        out += [f"No change against `{base_ref}`.", ""]
    else:
        out += [f"Total gates **{th:,}** against **{tb:,}** on `{base_ref}` "
                f"— {delta(tb, th)}.", ""]
    out += [
        "| Circuit | ACIR opcodes | Δ | Gates | Δ |",
        "|---|---:|---:|---:|---:|",
        *rows,
        "",
        f"<sub>`bb gates -t {TARGET}`, the target the freeze path writes VKs with. "
        "Gate count drives proving time, memory and the VK; opcodes drive witness "
        "generation.</sub>",
    ]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect")
    c.add_argument("noir", type=Path)
    c.add_argument("-o", "--output", type=Path, required=True)
    c.add_argument("--nargo", default="nargo")
    c.add_argument("--bb", default="bb")

    r = sub.add_parser("report")
    r.add_argument("base", type=Path)
    r.add_argument("head", type=Path)
    r.add_argument("--base-ref", default="base")

    a = ap.parse_args()
    if a.cmd == "collect":
        a.output.write_text(json.dumps(collect(a.noir, a.nargo, a.bb), indent=2, sort_keys=True))
        print(f"wrote {a.output}", file=sys.stderr)
    else:
        print(report(json.loads(a.base.read_text()),
                     json.loads(a.head.read_text()), a.base_ref))


if __name__ == "__main__":
    main()
