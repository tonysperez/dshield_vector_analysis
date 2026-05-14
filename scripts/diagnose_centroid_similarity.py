"""One-off diagnostic: pairwise cosine similarity between session-cluster centroids.

Determines whether the "HDBSCAN splits similar sessions" problem can be
addressed by a post-cluster merge layer (high pairwise sim between
near-duplicate centroids) or whether the real issue is upstream in the
feature pipeline (no near-duplicates → splits are genuine).

Pulls the centroids of the latest run_id from `session_clusters`, computes
all pairwise cosine similarities, and prints a histogram + the top-K most
similar centroid pairs along with their sample session ids.

Run from the repo root:
    python scripts/diagnose_centroid_similarity.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make the in-repo package importable without installing.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client


def main() -> int:
    cfg = load_config()
    secrets = load_secrets()
    es = make_client(cfg.elasticsearch, secrets)
    idx = cfg.elasticsearch.indexes.cowrie.session_clusters

    if not es.indices.exists(index=idx):
        print(f"ERROR: index {idx} does not exist. Run `cluster sessions` first.")
        return 1

    # Latest run_id.
    resp = es.search(
        index=idx,
        size=1,
        query={"term": {"doc_type": "cluster"}},
        sort=[{"@timestamp": "desc"}],
        _source=["run_id"],
    )
    hits = resp["hits"]["hits"]
    if not hits:
        print(f"ERROR: no cluster docs in {idx}.")
        return 1
    run_id = hits[0]["_source"]["run_id"]
    print(f"Latest run_id: {run_id}")

    # All centroids for that run.
    resp2 = es.search(
        index=idx,
        size=1000,
        query={"bool": {"must": [
            {"term": {"doc_type": "cluster"}},
            {"term": {"run_id": run_id}},
        ]}},
        _source=["cluster_id", "size", "centroid", "sample_session_ids",
                 "playbook_id", "playbook_name"],
    )
    docs = [h["_source"] for h in resp2["hits"]["hits"]]
    docs = [d for d in docs if d.get("centroid")]
    n = len(docs)
    print(f"Centroids loaded: {n}")
    if n < 2:
        print("Need ≥2 centroids for pairwise analysis.")
        return 0

    cluster_ids = [d["cluster_id"] for d in docs]
    sizes = [d.get("size", 0) for d in docs]
    pb_names = [d.get("playbook_name", "") for d in docs]
    sample_ids = [d.get("sample_session_ids", []) for d in docs]

    M = np.array([d["centroid"] for d in docs], dtype=np.float32)
    # Centroids are stored already mean-of-L2-normalized so they're not
    # unit vectors; normalize again for cosine sim.
    norms = np.linalg.norm(M, axis=1, keepdims=True)
    norms = np.where(norms == 0.0, 1.0, norms)
    Mn = M / norms
    sim = Mn @ Mn.T  # (n, n)
    np.fill_diagonal(sim, np.nan)  # exclude self-similarity

    upper = sim[np.triu_indices(n, k=1)]
    print()
    print("Pairwise cosine similarity distribution:")
    print(f"  pairs:  {len(upper)}")
    print(f"  min:    {np.nanmin(upper):.4f}")
    print(f"  p25:    {np.nanpercentile(upper, 25):.4f}")
    print(f"  median: {np.nanmedian(upper):.4f}")
    print(f"  p75:    {np.nanpercentile(upper, 75):.4f}")
    print(f"  p90:    {np.nanpercentile(upper, 90):.4f}")
    print(f"  p95:    {np.nanpercentile(upper, 95):.4f}")
    print(f"  p99:    {np.nanpercentile(upper, 99):.4f}")
    print(f"  max:    {np.nanmax(upper):.4f}")

    # Histogram in fixed bins so we can eyeball whether merge is warranted.
    print()
    print("Histogram (count of pairs in each cosine-sim band):")
    bands = [-1.0, 0.0, 0.5, 0.7, 0.8, 0.85, 0.9, 0.92, 0.94, 0.96, 0.98, 0.99, 1.0001]
    hist, _ = np.histogram(upper[~np.isnan(upper)], bins=bands)
    for lo, hi, c in zip(bands[:-1], bands[1:], hist):
        bar = "#" * min(60, c)
        print(f"  [{lo:>5.2f}, {hi:>5.2f}):  {c:>5d}  {bar}")

    # Top-K most similar pairs with cluster ids + sizes + names + sample sids.
    K = 20
    print()
    print(f"Top {K} most-similar centroid pairs:")
    flat_idx = np.argsort(-np.where(np.isnan(sim), -np.inf, sim), axis=None)
    seen: set[tuple[int, int]] = set()
    count = 0
    for fi in flat_idx:
        i, j = divmod(int(fi), n)
        if i >= j:
            continue
        if (i, j) in seen:
            continue
        seen.add((i, j))
        s = sim[i, j]
        if np.isnan(s):
            continue
        print(f"  sim={s:.4f}  "
              f"{cluster_ids[i]} (size={sizes[i]}, name='{pb_names[i]}') "
              f"<--> "
              f"{cluster_ids[j]} (size={sizes[j]}, name='{pb_names[j]}')")
        # First 2 sample session ids per side for spot-checking.
        si = sample_ids[i][:2]
        sj = sample_ids[j][:2]
        print(f"      samples_a: {si}")
        print(f"      samples_b: {sj}")
        count += 1
        if count >= K:
            break

    # Quick merge simulation: how many playbook groups would form at each threshold.
    print()
    print("Merge simulation (union-find at each threshold):")
    for tau in [0.99, 0.98, 0.96, 0.94, 0.92, 0.90, 0.85]:
        parent = list(range(n))
        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        for i in range(n):
            for j in range(i + 1, n):
                if not np.isnan(sim[i, j]) and sim[i, j] >= tau:
                    ri, rj = find(i), find(j)
                    if ri != rj:
                        parent[ri] = rj
        groups: dict[int, list[int]] = {}
        for i in range(n):
            r = find(i)
            groups.setdefault(r, []).append(i)
        sizes_per_group = sorted((len(g) for g in groups.values()), reverse=True)
        n_merged = sum(1 for g in groups.values() if len(g) > 1)
        largest = sizes_per_group[0] if sizes_per_group else 0
        print(f"  τ={tau:.2f}:  {n} clusters → {len(groups)} playbooks  "
              f"(merged_groups={n_merged}, largest_group={largest}, "
              f"top5_sizes={sizes_per_group[:5]})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
