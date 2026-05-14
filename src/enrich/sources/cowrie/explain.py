"""Cluster-pair explanation: why didn't two HDBSCAN session clusters merge?

The pipeline produces session clusters and (optionally) collapses
near-duplicate clusters into playbooks via
`merge_clusters_into_playbooks` ([sessions.py]). When two clusters with
the same LLM-generated `playbook_name` still don't merge, an analyst
typically wants to know why. This module gives a structured answer:

  - centroid cosine similarity vs. merge threshold
  - per-scalar mean / std diff
  - top-K command frequency table per cluster
  - command-set Jaccard + lists of "only A" / "only B" commands
  - off-centroid analysis: each unique command's cosine sim to both
    centroids (sorted by 'pull toward A')
  - 2 sample command sequences per cluster for spot-checking

The output is a pure dict (JSON-serialisable; no numpy). It is consumed
by both `scripts/explain_cluster_pair.py` (pretty-printed CLI) and the
console's `/compare` endpoint.

A separate LLM wrapper at `explain_cluster_pair_with_llm` takes the
structured analysis and asks the local LLM for a plain-language verdict
+ evidence + recommendation. The data analysis is fast (ES-only); the
LLM call is the slow part and is intentionally separated.
"""
from __future__ import annotations

import statistics
from pathlib import Path
from typing import Iterable, Optional

from elasticsearch import Elasticsearch

from ...config import AppConfig
from ...llm.schemas import CLUSTER_PAIR_EXPLANATION_JSON_SCHEMA, ClusterPairExplanation
from .commands import hash_command, normalize


SAMPLE_MEMBERS = 200
TOP_K_COMMANDS = 15
SAMPLE_SEQUENCES = 2
MAX_CMDS_PER_SEQUENCE = 15
SCALAR_KEYS = ("command_count", "unique_commands", "login_success_rate", "mean_novelty_score")


def _cosine(a, b) -> float:
    # Pure-Python cosine to keep this module numpy-free. Inputs are short
    # 768-element lists; the cost is fine and avoids a numpy dep on the
    # console side.
    if not a or not b:
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return 0.0
    return float(dot / ((na ** 0.5) * (nb ** 0.5)))


def _latest_run_id(es: Elasticsearch, clusters_idx: str) -> Optional[str]:
    resp = es.search(
        index=clusters_idx, size=1,
        query={"term": {"doc_type": "cluster"}},
        sort=[{"@timestamp": "desc"}],
        _source=["run_id"],
    )
    hits = resp["hits"]["hits"]
    return hits[0]["_source"]["run_id"] if hits else None


def _fetch_centroids(
    es: Elasticsearch, clusters_idx: str, run_id: str, cluster_ids: list[str],
) -> dict[str, dict]:
    resp = es.search(
        index=clusters_idx, size=len(cluster_ids),
        query={"bool": {"must": [
            {"term": {"doc_type": "cluster"}},
            {"term": {"run_id": run_id}},
            {"terms": {"cluster_id": cluster_ids}},
        ]}},
        _source=["cluster_id", "size", "centroid", "playbook_id", "playbook_name"],
    )
    return {h["_source"]["cluster_id"]: h["_source"] for h in resp["hits"]["hits"]}


def _fetch_members(es: Elasticsearch, sess_idx: str, cluster_id: str, cap: int) -> list[dict]:
    """Member sessions of an HDBSCAN cluster, with embedding and 4 scalars."""
    resp = es.search(
        index=sess_idx, size=cap,
        _source=[
            "cowrie.session_id",
            "dshield.cowrie.enrichment.session.embedding",
            "dshield.cowrie.enrichment.session.command_count",
            "dshield.cowrie.enrichment.session.unique_commands",
            "dshield.cowrie.enrichment.session.login_success_count",
            "dshield.cowrie.enrichment.session.login_fail_count",
            "dshield.cowrie.enrichment.session.mean_novelty_score",
        ],
        query={"term": {"dshield.cowrie.enrichment.session.cluster.id": cluster_id}},
    )
    out: list[dict] = []
    for h in resp["hits"]["hits"]:
        src = h["_source"]
        senr = (((src.get("dshield") or {}).get("cowrie") or {})
                .get("enrichment", {}).get("session", {}))
        if not senr.get("embedding"):
            continue
        sid = (src.get("cowrie") or {}).get("session_id") or h["_id"]
        success = senr.get("login_success_count") or 0
        fail    = senr.get("login_fail_count") or 0
        total   = success + fail
        out.append({
            "sid":                sid,
            "command_count":      float(senr.get("command_count") or 0),
            "unique_commands":    float(senr.get("unique_commands") or 0),
            "login_success_rate": (success / total) if total > 0 else 0.0,
            "mean_novelty_score": float(senr.get("mean_novelty_score") or 0.0),
        })
    return out


def _scalar_stats(members: list[dict]) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for k in SCALAR_KEYS:
        vals = [m[k] for m in members]
        if not vals:
            out[k] = {"mean": 0.0, "std": 0.0}
            continue
        mean = sum(vals) / len(vals)
        std  = statistics.stdev(vals) if len(vals) > 1 else 0.0
        out[k] = {"mean": float(mean), "std": float(std)}
    return out


def _top_commands(
    es: Elasticsearch, events_idx: str, session_ids: list[str], k: int,
) -> list[dict]:
    if not session_ids:
        return []
    resp = es.search(
        index=events_idx, size=0,
        query={"bool": {"must": [
            {"terms": {"cowrie.session_id": session_ids}},
            {"term": {"event.action": "cowrie.command.input"}},
        ]}},
        aggs={"by_cmd": {"terms": {"field": "process.command_line", "size": k}}},
    )
    return [
        {"command": b["key"], "count": int(b["doc_count"])}
        for b in resp.get("aggregations", {}).get("by_cmd", {}).get("buckets", [])
        if b.get("key")
    ]


def _command_centroid_sims(
    es: Elasticsearch, cmds_idx: str, command_lines: Iterable[str],
    centroid_a: list[float], centroid_b: list[float], max_chars: int,
) -> list[dict]:
    items: list[tuple[str, str]] = []
    for cl in command_lines:
        norm, _ = normalize(cl, max_chars)
        if not norm:
            continue
        items.append((cl, hash_command(norm)))
    if not items:
        return []
    hashes = [h for _, h in items]
    resp = es.mget(index=cmds_idx, ids=hashes)
    emb_by_hash: dict[str, list[float]] = {}
    for d in resp["docs"]:
        if not d.get("found"):
            continue
        src = d.get("_source") or {}
        emb = (((src.get("dshield") or {}).get("cowrie") or {})
               .get("enrichment", {}).get("embedding"))
        if emb:
            emb_by_hash[d["_id"]] = emb

    rows: list[dict] = []
    for cl, h in items:
        emb = emb_by_hash.get(h)
        if emb is None:
            rows.append({"command": cl, "sim_a": None, "sim_b": None, "diff": None})
            continue
        sa = _cosine(emb, centroid_a)
        sb = _cosine(emb, centroid_b)
        rows.append({"command": cl, "sim_a": sa, "sim_b": sb, "diff": sa - sb})
    rows.sort(key=lambda r: -(r["diff"] if r["diff"] is not None else -999))
    return rows


def _fetch_command_sequences(
    es: Elasticsearch, events_idx: str, session_ids: list[str], max_per: int,
) -> list[dict]:
    if not session_ids:
        return []
    resp = es.search(
        index=events_idx, size=10000,
        _source=["cowrie.session_id", "process.command_line", "@timestamp"],
        query={"bool": {"must": [
            {"terms": {"cowrie.session_id": session_ids}},
            {"term": {"event.action": "cowrie.command.input"}},
        ]}},
        sort=[{"@timestamp": "asc"}],
    )
    by_sid: dict[str, list[str]] = {sid: [] for sid in session_ids}
    for h in resp["hits"]["hits"]:
        src = h["_source"]
        sid = (src.get("cowrie") or {}).get("session_id")
        cmd = (src.get("process") or {}).get("command_line")
        if sid in by_sid and cmd:
            by_sid[sid].append(cmd)
    # Preserve caller's session order; truncate per-session.
    return [
        {"sid": sid, "total_commands": len(cmds), "commands": cmds[:max_per]}
        for sid, cmds in by_sid.items()
    ]


def analyze_cluster_pair(
    es: Elasticsearch, cfg: AppConfig, a_id: str, b_id: str,
) -> dict:
    """Structured analysis of why two HDBSCAN session clusters didn't merge.

    Returns a JSON-serialisable dict with: centroid sim, scalar
    distributions, top-K commands per cluster, command-set diff,
    off-centroid sims for unique commands, and 2 sample command
    sequences per cluster.

    Raises:
        RuntimeError: if the cluster index is empty or a requested
            cluster_id is missing from the latest run.
    """
    sess_idx     = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    events_idx   = cfg.elasticsearch.indexes.cowrie.sessions_raw
    cmds_idx     = cfg.elasticsearch.indexes.cowrie.commands

    run_id = _latest_run_id(es, clusters_idx)
    if not run_id:
        raise RuntimeError(f"No cluster docs in {clusters_idx}")

    centroids = _fetch_centroids(es, clusters_idx, run_id, [a_id, b_id])
    missing = [c for c in (a_id, b_id) if c not in centroids]
    if missing:
        raise RuntimeError(
            f"cluster(s) not found in run {run_id}: {missing}"
        )

    cent_a = centroids[a_id]
    cent_b = centroids[b_id]

    sim = _cosine(cent_a["centroid"], cent_b["centroid"])
    threshold = cfg.session.playbook_merge_threshold

    members_a = _fetch_members(es, sess_idx, a_id, SAMPLE_MEMBERS)
    members_b = _fetch_members(es, sess_idx, b_id, SAMPLE_MEMBERS)

    scalars_a = _scalar_stats(members_a)
    scalars_b = _scalar_stats(members_b)

    sids_a = [m["sid"] for m in members_a]
    sids_b = [m["sid"] for m in members_b]
    top_a = _top_commands(es, events_idx, sids_a, TOP_K_COMMANDS)
    top_b = _top_commands(es, events_idx, sids_b, TOP_K_COMMANDS)

    set_a = {t["command"] for t in top_a}
    set_b = {t["command"] for t in top_b}
    overlap = sorted(set_a & set_b)
    only_a  = sorted(set_a - set_b)
    only_b  = sorted(set_b - set_a)
    union   = set_a | set_b
    jaccard = (len(overlap) / len(union)) if union else 0.0

    off_centroid_a = _command_centroid_sims(
        es, cmds_idx, only_a, cent_a["centroid"], cent_b["centroid"],
        cfg.worker.command_max_chars,
    )
    off_centroid_b = _command_centroid_sims(
        es, cmds_idx, only_b, cent_a["centroid"], cent_b["centroid"],
        cfg.worker.command_max_chars,
    )

    seqs_a = _fetch_command_sequences(es, events_idx, sids_a[:SAMPLE_SEQUENCES], MAX_CMDS_PER_SEQUENCE)
    seqs_b = _fetch_command_sequences(es, events_idx, sids_b[:SAMPLE_SEQUENCES], MAX_CMDS_PER_SEQUENCE)

    scalars_combined: dict[str, dict] = {}
    for k in SCALAR_KEYS:
        a = scalars_a[k]
        b = scalars_b[k]
        scalars_combined[k] = {
            "a_mean": a["mean"], "a_std": a["std"],
            "b_mean": b["mean"], "b_std": b["std"],
            "delta":  a["mean"] - b["mean"],
        }

    return {
        "run_id":              run_id,
        "merge_threshold":     threshold,
        "scalar_weight":       cfg.session.cluster_scalar_weight,
        "centroid_similarity": sim,
        "gap_to_merge":        threshold - sim,
        "would_merge":         sim >= threshold,
        "a": {
            "cluster_id":    a_id,
            "size":          int(cent_a.get("size") or 0),
            "playbook_id":   cent_a.get("playbook_id"),
            "playbook_name": cent_a.get("playbook_name"),
            "members_sampled": len(members_a),
        },
        "b": {
            "cluster_id":    b_id,
            "size":          int(cent_b.get("size") or 0),
            "playbook_id":   cent_b.get("playbook_id"),
            "playbook_name": cent_b.get("playbook_name"),
            "members_sampled": len(members_b),
        },
        "scalars":             scalars_combined,
        "top_commands_a":      top_a,
        "top_commands_b":      top_b,
        "command_set_diff": {
            "jaccard":   jaccard,
            "shared":    overlap,
            "only_a":    only_a,
            "only_b":    only_b,
        },
        "off_centroid_a":      off_centroid_a,
        "off_centroid_b":      off_centroid_b,
        "sample_sequences_a":  seqs_a,
        "sample_sequences_b":  seqs_b,
    }


def explain_cluster_pair_with_llm(
    cfg: AppConfig, analysis: dict,
) -> dict:
    """Take a structured analysis dict and ask the local LLM for a plain-
    language verdict + evidence + recommendation. Always uses the local
    LLM, never cloud (these are non-critical narrative outputs).

    Returns a dict with `verdict`, `evidence`, `recommendation`, `rationale`.
    Raises RuntimeError if the prompt is not configured or the LLM fails
    schema validation.
    """
    if not getattr(cfg.prompts, "cluster_pair_explanation", None):
        raise RuntimeError(
            "prompts.cluster_pair_explanation is unset; cannot generate LLM narrative."
        )

    prompt_template = Path(cfg.prompts.cluster_pair_explanation).read_text()
    prompt = _render_explanation_prompt(prompt_template, analysis)

    # Local LLM only — keep cloud out of narrative generation per project
    # convention for non-critical LLM tasks (matches playbook naming).
    from ...llm import make_llm_client
    with make_llm_client(cfg.llm) as llm:
        raw = llm.generate_json(
            prompt,
            schema=CLUSTER_PAIR_EXPLANATION_JSON_SCHEMA,
            schema_name="cluster_pair_explanation",
            options={"max_tokens": 1024},
        )
    parsed = ClusterPairExplanation.model_validate_json(raw)
    return parsed.model_dump()


def _render_explanation_prompt(template: str, a: dict) -> str:
    """Curated subset of the analysis → prompt placeholders. Skip
    sequences and off-centroid tables (numeric noise that distracts the
    LLM); pass top commands, scalars, set diff, and the headline numbers."""
    def _commands_block(top: list[dict]) -> str:
        if not top:
            return "  (no commands)"
        return "\n".join(f"  [{t['count']:>4}] {t['command']}" for t in top)

    def _scalars_block(side: str) -> str:
        lines = []
        for k, vs in a["scalars"].items():
            mean = vs[f"{side}_mean"]
            std  = vs[f"{side}_std"]
            lines.append(f"  {k}: mean={mean:.3f}, std={std:.3f}")
        return "\n".join(lines)

    only_a = a["command_set_diff"]["only_a"]
    only_b = a["command_set_diff"]["only_b"]
    shared = a["command_set_diff"]["shared"]

    return (
        template
        .replace("<<<MERGE_THRESHOLD>>>",       f"{a['merge_threshold']:.3f}")
        .replace("<<<SCALAR_WEIGHT>>>",         f"{a['scalar_weight']:.3f}")
        .replace("<<<CENTROID_SIMILARITY>>>",   f"{a['centroid_similarity']:.4f}")
        .replace("<<<GAP_TO_MERGE>>>",          f"{a['gap_to_merge']:+.4f}")
        .replace("<<<WOULD_MERGE>>>",           "yes" if a["would_merge"] else "no")
        .replace("<<<A_ID>>>",                  a["a"]["cluster_id"])
        .replace("<<<A_SIZE>>>",                str(a["a"]["size"]))
        .replace("<<<A_NAME>>>",                a["a"].get("playbook_name") or "(unnamed)")
        .replace("<<<A_SCALARS>>>",             _scalars_block("a"))
        .replace("<<<A_TOP_COMMANDS>>>",        _commands_block(a["top_commands_a"]))
        .replace("<<<B_ID>>>",                  a["b"]["cluster_id"])
        .replace("<<<B_SIZE>>>",                str(a["b"]["size"]))
        .replace("<<<B_NAME>>>",                a["b"].get("playbook_name") or "(unnamed)")
        .replace("<<<B_SCALARS>>>",             _scalars_block("b"))
        .replace("<<<B_TOP_COMMANDS>>>",        _commands_block(a["top_commands_b"]))
        .replace("<<<JACCARD>>>",               f"{a['command_set_diff']['jaccard']:.3f}")
        .replace("<<<SHARED_COUNT>>>",          str(len(shared)))
        .replace("<<<ONLY_A_COMMANDS>>>",       ", ".join(only_a) or "(none)")
        .replace("<<<ONLY_B_COMMANDS>>>",       ", ".join(only_b) or "(none)")
    )
