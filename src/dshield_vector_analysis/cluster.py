"""Phase 3: HDBSCAN clustering + novelty scoring over all command embeddings.

Standalone worker — no LLM required. Reads embeddings already stored in the
enrichment index, clusters them, then bulk-updates cluster.{id,novelty_score,
is_outlier,scored_at} on every enrichment doc and writes centroid docs to the
clusters index.

Install cluster deps first:  pip install -e ".[cluster]"
"""
from __future__ import annotations

import logging
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Iterator

from elasticsearch import Elasticsearch

from .config import AppConfig, ClusterConfig, Secrets
from .es_client import bulk_write, init_index, make_client

log = logging.getLogger(__name__)

try:
    import numpy as np
    from sklearn.cluster import HDBSCAN as _HDBSCAN
    _CLUSTER_DEPS = True
except ImportError:
    _CLUSTER_DEPS = False
    np = None  # type: ignore[assignment]
    _HDBSCAN = None  # type: ignore[assignment]

_SAMPLE_SIZE = 5  # commands to store per cluster centroid doc
# Relative to CWD (project root). Matches the convention used by `init-index --mapping`.
_CLUSTERS_MAPPING = "es-mappings/dshield-cowrie-clusters-mapping.json"

_CLUSTER_UPDATE_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "def en = ctx._source.dshield.cowrie.enrichment;"
    "if (en.cluster == null) { en.cluster = [:]; }"
    "en.cluster.id = params.cluster_id;"
    "en.cluster.novelty_score = params.novelty_score;"
    "en.cluster.is_outlier = params.is_outlier;"
    "en.cluster.scored_at = params.scored_at;"
)


def get_clusters_index(cfg: AppConfig) -> str:
    if cfg.cluster.clusters_index:
        return cfg.cluster.clusters_index
    base = cfg.elasticsearch.enrichment_index
    if base.endswith("-default"):
        return base[: -len("-default")] + "-clusters-default"
    return base + "-clusters"


def iter_enriched_docs(
    es: Elasticsearch,
    index: str,
    page_size: int = 1000,
) -> Iterator[tuple[str, list[float], str]]:
    """Yield (doc_id, embedding, command) for all docs that have an embedding."""
    body: dict = {
        "size": page_size,
        "_source": ["dshield.cowrie.enrichment.embedding", "process.command_line"],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            emb = (
                ((src.get("dshield") or {}).get("cowrie") or {})
                .get("enrichment", {})
                .get("embedding")
            )
            if not emb:
                continue
            cmd = (src.get("process") or {}).get("command_line", "")
            yield h["_id"], emb, cmd
        search_after = hits[-1]["sort"]


def l2_normalize(matrix: "np.ndarray") -> "np.ndarray":
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms = np.where(norms == 0.0, 1.0, norms)
    return matrix / norms


def compute_centroids(
    matrix: "np.ndarray", labels: "np.ndarray"
) -> dict[int, "np.ndarray"]:
    centroids: dict[int, "np.ndarray"] = {}
    for lbl in np.unique(labels):
        if lbl < 0:
            continue
        mask = labels == lbl
        centroids[int(lbl)] = matrix[mask].mean(axis=0)
    return centroids


def novelty_score(normalized_emb: "np.ndarray", centroids: dict[int, "np.ndarray"]) -> float:
    """1 - max cosine_sim to any centroid. embedding must already be L2-normalized."""
    if not centroids:
        return 1.0
    best = -1.0
    for c in centroids.values():
        norm_c = float(np.linalg.norm(c))
        if norm_c == 0.0:
            continue
        sim = float(np.dot(normalized_emb, c)) / norm_c
        if sim > best:
            best = sim
    return float(1.0 - max(0.0, best))


def load_centroids(es: Elasticsearch, clusters_index: str) -> list[list[float]]:
    """Load centroid vectors from the latest cluster run in ES.

    Returns [] if the index doesn't exist, has no data, or any query fails.
    Called by enrich.py to populate the novel_embedding triage rule.
    """
    try:
        if not es.indices.exists(index=clusters_index):
            return []
        resp = es.search(
            index=clusters_index,
            **{
                "size": 1,
                "query": {"term": {"doc_type": "cluster"}},
                "sort": [{"@timestamp": "desc"}],
                "_source": ["run_id"],
            },
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return []
        run_id = hits[0]["_source"].get("run_id")
        if not run_id:
            return []

        resp2 = es.search(
            index=clusters_index,
            **{
                "size": 1000,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"doc_type": "cluster"}},
                            {"term": {"run_id": run_id}},
                        ]
                    }
                },
                "_source": ["centroid"],
            },
        )
        return [
            h["_source"]["centroid"]
            for h in resp2["hits"]["hits"]
            if h["_source"].get("centroid")
        ]
    except Exception as exc:
        log.warning("Could not load centroids from %s: %s", clusters_index, exc)
        return []


def novelty_score_from_lists(
    embedding: list[float],
    centroids: list[list[float]],
) -> float:
    """Pure-Python novelty score for use in triage (no numpy dependency there)."""
    if not centroids:
        return 1.0
    best = -1.0
    for c in centroids:
        dot = sum(a * b for a, b in zip(embedding, c))
        norm_c = math.sqrt(sum(b * b for b in c))
        if norm_c == 0.0:
            continue
        sim = dot / norm_c
        if sim > best:
            best = sim
    return float(1.0 - max(0.0, best))


def run(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """Main cluster entry point. Returns stats dict."""
    if not _CLUSTER_DEPS:
        raise ImportError(
            "Phase 3 cluster deps not installed. Run: pip install -e '.[cluster]'"
        )

    t_start = time.monotonic()
    es = make_client(cfg.elasticsearch, secrets)
    clusters_idx = get_clusters_index(cfg)
    enrich_idx = cfg.elasticsearch.enrichment_index
    ccfg: ClusterConfig = cfg.cluster

    if not es.indices.exists(index=enrich_idx):
        raise RuntimeError(
            f"Enrichment index '{enrich_idx}' not found. "
            "Run Phase 1 first (dshield_vector_analysis enrich), or check "
            "elasticsearch.enrichment_index in config/local.yaml."
        )

    # --- 1. Pull all embeddings --------------------------------------------------
    log.info("Fetching embeddings from %s ...", enrich_idx)
    doc_ids: list[str] = []
    embeddings_list: list[list[float]] = []
    commands: list[str] = []

    for doc_id, emb, cmd in iter_enriched_docs(es, enrich_idx, ccfg.page_size):
        doc_ids.append(doc_id)
        embeddings_list.append(emb)
        commands.append(cmd)

    n_docs = len(doc_ids)
    log.info("Fetched %d docs with embeddings", n_docs)

    if n_docs < ccfg.min_cluster_size:
        log.warning(
            "Too few docs (%d) for clustering (min_cluster_size=%d); skipping",
            n_docs,
            ccfg.min_cluster_size,
        )
        return {"docs_fetched": n_docs, "status": "skipped_too_few", "dry_run": dry_run}

    # --- 2. Build matrix + L2-normalize -----------------------------------------
    matrix = np.array(embeddings_list, dtype=np.float32)
    del embeddings_list  # free raw lists
    normalized = l2_normalize(matrix)
    del matrix  # normalized copy is all we need from here on

    # --- 3. HDBSCAN ---------------------------------------------------------------
    log.info("Running HDBSCAN (min_cluster_size=%d, min_samples=%d) on %d docs ...",
             ccfg.min_cluster_size, ccfg.min_samples, n_docs)
    clusterer = _HDBSCAN(
        min_cluster_size=ccfg.min_cluster_size,
        min_samples=ccfg.min_samples,
        metric="euclidean",
    )
    labels = clusterer.fit_predict(normalized)

    unique_labels = [int(l) for l in np.unique(labels)]
    cluster_labels = [l for l in unique_labels if l >= 0]
    n_clusters = len(cluster_labels)
    n_outliers = int(np.sum(labels == -1))
    log.info("HDBSCAN: %d clusters, %d outliers", n_clusters, n_outliers)

    # --- 4. Compute centroids + sample commands -----------------------------------
    centroids = compute_centroids(normalized, labels)

    # Collect sample commands per cluster (first _SAMPLE_SIZE seen)
    sample_map: dict[int, list[str]] = {lbl: [] for lbl in cluster_labels}
    for lbl, cmd in zip(labels, commands):
        lbl = int(lbl)
        if lbl >= 0 and len(sample_map[lbl]) < _SAMPLE_SIZE:
            sample_map[lbl].append(cmd)

    # --- 5. Compute per-doc novelty + build bulk update actions ------------------
    now_str = datetime.now(timezone.utc).isoformat()
    run_id = str(uuid.uuid4())

    update_actions: list[dict] = []
    for i, (doc_id, lbl) in enumerate(zip(doc_ids, labels)):
        lbl = int(lbl)
        is_outlier = lbl < 0
        cluster_id = "outlier" if is_outlier else f"cluster_{lbl}"
        score = 1.0 if is_outlier else novelty_score(normalized[i], centroids)

        update_actions.append({
            "_op_type": "update",
            "_id": doc_id,
            "script": {
                "source": _CLUSTER_UPDATE_SCRIPT,
                "params": {
                    "cluster_id": cluster_id,
                    "novelty_score": round(score, 6),
                    "is_outlier": is_outlier,
                    "scored_at": now_str,
                },
            },
        })

    # --- 6. Write centroid docs to clusters index ---------------------------------
    cluster_docs: list[dict] = []
    for lbl, centroid_vec in centroids.items():
        cluster_docs.append({
            "_op_type": "index",
            "_source": {
                "@timestamp": now_str,
                "run_id": run_id,
                "doc_type": "cluster",
                "cluster_id": f"cluster_{lbl}",
                "size": int(np.sum(labels == lbl)),
                "centroid": centroid_vec.tolist(),
                "sample_commands": sample_map.get(lbl, []),
            },
        })
    # Summary doc
    cluster_docs.append({
        "_op_type": "index",
        "_source": {
            "@timestamp": now_str,
            "run_id": run_id,
            "doc_type": "run_summary",
            "total_docs": n_docs,
            "n_clusters": n_clusters,
            "n_outliers": n_outliers,
            "runtime_seconds": round(time.monotonic() - t_start, 2),
        },
    })

    # --- 7. Flush to ES -----------------------------------------------------------
    stats: dict = {
        "run_id": run_id,
        "docs_fetched": n_docs,
        "n_clusters": n_clusters,
        "n_outliers": n_outliers,
        "dry_run": dry_run,
    }

    if dry_run:
        log.info("dry-run: skipping all ES writes")
        stats["status"] = "dry_run"
        return stats

    # Ensure clusters index exists
    init_index(es, _CLUSTERS_MAPPING, clusters_idx)

    # Write centroid + summary docs
    ok, errs = bulk_write(es, clusters_idx, cluster_docs)
    stats["cluster_docs_written"] = ok
    stats["cluster_doc_errors"] = len(errs)
    if errs:
        log.warning("cluster index bulk errors (%d): %s", len(errs), errs[:2])

    # Bulk-update enrichment docs in batches
    bulk_ok = 0
    bulk_errors = 0
    batch = ccfg.batch_size
    for start in range(0, len(update_actions), batch):
        chunk = update_actions[start : start + batch]
        ok, errs = bulk_write(es, enrich_idx, chunk)
        bulk_ok += ok
        bulk_errors += len(errs)
        if errs:
            log.warning("enrichment update errors (%d): %s", len(errs), errs[:2])
        log.debug("Updated %d/%d enrichment docs", start + len(chunk), n_docs)

    stats["docs_updated"] = bulk_ok
    stats["bulk_errors"] = bulk_errors
    stats["runtime_seconds"] = round(time.monotonic() - t_start, 2)
    stats["clusters_index"] = clusters_idx
    return stats
