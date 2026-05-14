"""Explain why two HDBSCAN session clusters didn't merge.

Thin CLI wrapper around `dshield_enrich.sources.cowrie.explain.analyze_cluster_pair`
(structured analysis) and `explain_cluster_pair_with_llm` (optional plain-
language LLM narrative). Pretty-prints the analysis to stdout.

Run from repo root:
    PYTHONPATH=/home/styx/git/dshield_vector_analysis/src \\
      /home/styx/git/dshield_vector_analysis/console/.venv/bin/python \\
      scripts/explain_cluster_pair.py --pair cluster_9 cluster_12

Add --explain to also call the local LLM for a verdict + recommendation.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dshield_enrich.config import load_config, load_secrets
from dshield_enrich.es_client import make_client
from dshield_enrich.sources.cowrie.explain import (
    analyze_cluster_pair, explain_cluster_pair_with_llm,
)


LINE_WIDTH = 72


def fmt(s: str, w: int = LINE_WIDTH) -> str:
    s = (s or "").replace("\n", "\\n").replace("\t", " ")
    return s if len(s) <= w else s[: w - 1] + "…"


def section(title: str) -> None:
    print()
    print(f"--- {title} " + "-" * max(0, 78 - len(title) - 5))


def _print(a: dict) -> None:
    a_id = a["a"]["cluster_id"]
    b_id = a["b"]["cluster_id"]

    print(f"Latest run_id: {a['run_id']}")
    print(f"Comparing:     {a_id}  vs  {b_id}")

    section("Cluster metadata")
    for cd in (a["a"], a["b"]):
        print(f"  {cd['cluster_id']}: size={cd['size']:>4}  "
              f"playbook_id={cd.get('playbook_id') or '(unnamed)'}  "
              f"name='{cd.get('playbook_name') or ''}'")

    section("Centroid similarity (embedding space — what the merge layer sees)")
    sim = a["centroid_similarity"]
    threshold = a["merge_threshold"]
    gap = a["gap_to_merge"]
    print(f"  cosine_similarity = {sim:.4f}")
    print(f"  merge threshold   = {threshold:.4f}")
    print(f"  gap to merge      = {gap:+.4f}  "
          f"({'would merge at this τ' if a['would_merge'] else 'BELOW threshold, did not merge'})")
    print(f"  members sampled:  {a_id}={a['a']['members_sampled']}, "
          f"{b_id}={a['b']['members_sampled']}")

    section("Scalar distributions (the 4 behavioural features HDBSCAN saw)")
    print(f"  {'scalar':<22}  {a_id:>22}  {b_id:>22}   delta")
    for k, vs in a["scalars"].items():
        print(f"  {k:<22}  "
              f"{vs['a_mean']:>8.3f} ± {vs['a_std']:<8.3f}  "
              f"{vs['b_mean']:>8.3f} ± {vs['b_std']:<8.3f}  {vs['delta']:+8.3f}")
    print(f"\n  Reminder: HDBSCAN clustered on [768-dim embedding | 4 scalars × {a['scalar_weight']}].")
    print( "  Even small scalar deltas widen the Euclidean distance HDBSCAN saw —")
    print( "  a split between clusters with near-identical embeddings is often scalar-driven.")

    section("Top commands per cluster (by occurrence in sampled sessions)")
    for label, top in [(a_id, a["top_commands_a"]), (b_id, a["top_commands_b"])]:
        print(f"\n  {label}:")
        if not top:
            print("    (no commands found)")
        for t in top:
            print(f"    [{t['count']:>4}]  {fmt(t['command'])}")

    diff = a["command_set_diff"]
    section("Command-set diff (top-K only)")
    print(f"  jaccard:  {diff['jaccard']:.3f}  "
          f"({len(diff['shared'])} shared / "
          f"{len(set(diff['shared']) | set(diff['only_a']) | set(diff['only_b']))} union)")
    print(f"  shared:   {len(diff['shared'])} command(s)")
    print(f"  only A:   {len(diff['only_a'])} command(s)")
    print(f"  only B:   {len(diff['only_b'])} command(s)")

    if a["off_centroid_a"]:
        section(f"Commands only in {a_id} — sim to each centroid "
                f"(sorted by 'pulls toward {a_id}')")
        print(f"  {'cmd':<{LINE_WIDTH}}  sim→A    sim→B     diff")
        for r in a["off_centroid_a"]:
            ssa = f"{r['sim_a']:.3f}" if r['sim_a'] is not None else "  n/a"
            ssb = f"{r['sim_b']:.3f}" if r['sim_b'] is not None else "  n/a"
            df  = f"{r['diff']:+.3f}" if r['diff']  is not None else "  n/a"
            print(f"  {fmt(r['command']):<{LINE_WIDTH}}  {ssa}    {ssb}    {df}")

    if a["off_centroid_b"]:
        section(f"Commands only in {b_id} — sim to each centroid "
                f"(sorted by 'pulls toward {a_id}')")
        print(f"  {'cmd':<{LINE_WIDTH}}  sim→A    sim→B     diff")
        for r in a["off_centroid_b"]:
            ssa = f"{r['sim_a']:.3f}" if r['sim_a'] is not None else "  n/a"
            ssb = f"{r['sim_b']:.3f}" if r['sim_b'] is not None else "  n/a"
            df  = f"{r['diff']:+.3f}" if r['diff']  is not None else "  n/a"
            print(f"  {fmt(r['command']):<{LINE_WIDTH}}  {ssa}    {ssb}    {df}")

    section("Sample command sequences")
    for label, seqs in [(a_id, a["sample_sequences_a"]), (b_id, a["sample_sequences_b"])]:
        print(f"\n  {label}:")
        for s in seqs:
            print(f"    session {s['sid']}  ({s['total_commands']} command events)")
            for c in s["commands"]:
                print(f"      | {fmt(c)}")
            if s["total_commands"] > len(s["commands"]):
                print(f"      | ... +{s['total_commands'] - len(s['commands'])} more")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pair", nargs=2, required=True,
                    metavar=("CLUSTER_A", "CLUSTER_B"),
                    help="Two cluster_ids from the latest session_clusters run")
    ap.add_argument("--explain", action="store_true",
                    help="Also call the local LLM for a plain-language verdict")
    args = ap.parse_args()
    a_id, b_id = args.pair

    cfg = load_config()
    secrets = load_secrets()
    es = make_client(cfg.elasticsearch, secrets)

    try:
        analysis = analyze_cluster_pair(es, cfg, a_id, b_id)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    _print(analysis)

    if args.explain:
        section("Plain-language explanation (local LLM)")
        try:
            narrative = explain_cluster_pair_with_llm(cfg, analysis)
        except Exception as exc:
            print(f"  LLM call failed: {exc}")
            return 0
        print(f"  verdict:        {narrative['verdict']}")
        print(f"  recommendation: {narrative['recommendation']}")
        print(f"  evidence:       {narrative['evidence']}")
        if narrative.get("rationale"):
            print(f"  rationale:      {narrative['rationale']}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
