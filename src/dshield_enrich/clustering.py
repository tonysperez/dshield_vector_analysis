"""Shared HDBSCAN core. Layer-agnostic — used by every per-source clusterer.

Each source module (sources/<source>/<layer>.py) supplies:
- iter docs from its index, yielding (doc_id, embedding, label, scalars)
- a scalar-block builder (n × k normalized features)
- an ES update script + centroid sample-field name

This module owns the math: L2-normalize, scalar augmentation, HDBSCAN call,
centroid + novelty score computation.
"""
from __future__ import annotations

import logging
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Iterator

from elasticsearch import Elasticsearch

from .es_client import bulk_write, init_index

log = logging.getLogger(__name__)

try:
    import numpy as np
    from sklearn.cluster import HDBSCAN as _HDBSCAN
    _CLUSTER_DEPS = True
except ImportError:
    _CLUSTER_DEPS = False
    np = None  # type: ignore[assignment]
    _HDBSCAN = None  # type: ignore[assignment]


def cluster_deps_available() -> bool:
    return _CLUSTER_DEPS


def require_cluster_deps() -> None:
    if not _CLUSTER_DEPS:
        raise ImportError(
            "Cluster deps not installed. Run: pip install -e '.[cluster]'"
        )


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


def novelty_score_from_lists(
    embedding: list[float],
    centroids: list[list[float]],
) -> float:
    """Pure-Python novelty score for triage (no numpy dependency)."""
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


def load_centroids(es: Elasticsearch, clusters_index: str) -> list[list[float]]:
    """Load centroid vectors from the latest cluster run in ES.

    Returns [] if the index doesn't exist, has no data, or any query fails.
    Used by triage.py to populate the novel_embedding rule.
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


def run_layer_clustering(
    *,
    es: Elasticsearch,
    docs_iter: Iterator[tuple[str, list[float], str, dict]],
    docs_index: str,
    clusters_index: str,
    mapping_path: str,
    update_script: str,
    scalar_block_builder: Callable[[list[dict], float], "np.ndarray"],
    min_cluster_size: int,
    min_samples: int,
    scalar_weight: float,
    batch_size: int,
    sample_size: int,
    centroid_sample_field: str,
    dry_run: bool,
    layer_label: str,
) -> dict:
    """Generic HDBSCAN pipeline for one layer (commands / sessions / IPs / future).

    Steps:
      1. Pull all (doc_id, embedding, label, scalars) from docs_iter.
      2. L2-normalize embeddings -> n×D matrix.
      3. Optionally hstack a weighted scalar block.
      4. Run HDBSCAN.
      5. Compute centroids from the pure embedding matrix.
      6. Score novelty per doc against centroids.
      7. Bulk-update doc cluster fields via update_script.
      8. Write centroid + run_summary docs to clusters_index.

    Centroids are computed from pure embeddings (not scalar-augmented) so
    centroid storage and triage scoring stay consistent across layers.
    """
    require_cluster_deps()

    t_start = time.monotonic()

    doc_ids: list[str] = []
    embeddings_list: list[list[float]] = []
    labels_list: list[str] = []  # human-readable label per doc (e.g. command text, session_id)
    scalars_list: list[dict] = []

    for doc_id, emb, label, scalars in docs_iter:
        doc_ids.append(doc_id)
        embeddings_list.append(emb)
        labels_list.append(label)
        scalars_list.append(scalars)

    n_docs = len(doc_ids)
    log.info("[%s] Fetched %d docs with embeddings", layer_label, n_docs)

    if n_docs < min_cluster_size:
        log.warning(
            "[%s] Too few docs (%d) for clustering (min_cluster_size=%d); skipping",
            layer_label, n_docs, min_cluster_size,
        )
        return {"docs_fetched": n_docs, "status": "skipped_too_few", "dry_run": dry_run}

    matrix = np.array(embeddings_list, dtype=np.float32)
    del embeddings_list
    normalized = l2_normalize(matrix)
    del matrix

    cluster_matrix = normalized
    if scalar_weight > 0.0:
        scalar_block = scalar_block_builder(scalars_list, scalar_weight)
        cluster_matrix = np.hstack([normalized, scalar_block])
        log.info(
            "[%s] scalar augmentation: weight=%.3f matrix shape=%s",
            layer_label, scalar_weight, cluster_matrix.shape,
        )
    del scalars_list

    log.info(
        "[%s] Running HDBSCAN (min_cluster_size=%d, min_samples=%d) on %d docs ...",
        layer_label, min_cluster_size, min_samples, n_docs,
    )
    clusterer = _HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    )
    cluster_labels_arr = clusterer.fit_predict(cluster_matrix)
    del cluster_matrix

    unique_labels = [int(l) for l in np.unique(cluster_labels_arr)]
    valid_cluster_ids = [l for l in unique_labels if l >= 0]
    n_clusters = len(valid_cluster_ids)
    n_outliers = int(np.sum(cluster_labels_arr == -1))
    log.info("[%s] HDBSCAN: %d clusters, %d outliers", layer_label, n_clusters, n_outliers)

    centroids = compute_centroids(normalized, cluster_labels_arr)

    sample_map: dict[int, list[str]] = {lbl: [] for lbl in valid_cluster_ids}
    for lbl, label_text in zip(cluster_labels_arr, labels_list):
        lbl = int(lbl)
        if lbl >= 0 and len(sample_map[lbl]) < sample_size:
            sample_map[lbl].append(label_text)

    now_str = datetime.now(timezone.utc).isoformat()
    run_id = str(uuid.uuid4())

    update_actions: list[dict] = []
    for i, (doc_id, lbl) in enumerate(zip(doc_ids, cluster_labels_arr)):
        lbl = int(lbl)
        is_outlier = lbl < 0
        cluster_id = "outlier" if is_outlier else f"cluster_{lbl}"
        score = 1.0 if is_outlier else novelty_score(normalized[i], centroids)
        update_actions.append({
            "_op_type": "update",
            "_id": doc_id,
            "script": {
                "source": update_script,
                "params": {
                    "cluster_id": cluster_id,
                    "novelty_score": round(score, 6),
                    "is_outlier": is_outlier,
                    "scored_at": now_str,
                },
            },
        })

    cluster_docs: list[dict] = []
    for lbl, centroid_vec in centroids.items():
        cluster_docs.append({
            "_op_type": "index",
            "_source": {
                "@timestamp": now_str,
                "run_id": run_id,
                "doc_type": "cluster",
                "cluster_id": f"cluster_{lbl}",
                "size": int(np.sum(cluster_labels_arr == lbl)),
                "centroid": centroid_vec.tolist(),
                centroid_sample_field: sample_map.get(lbl, []),
            },
        })
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

    stats: dict = {
        "run_id": run_id,
        "docs_fetched": n_docs,
        "n_clusters": n_clusters,
        "n_outliers": n_outliers,
        "dry_run": dry_run,
    }

    if dry_run:
        log.info("[%s] dry-run: skipping all ES writes", layer_label)
        stats["status"] = "dry_run"
        return stats

    init_index(es, mapping_path, clusters_index)

    ok, errs = bulk_write(es, clusters_index, cluster_docs)
    stats["cluster_docs_written"] = ok
    stats["cluster_doc_errors"] = len(errs)
    if errs:
        log.warning("[%s] cluster index bulk errors (%d): %s", layer_label, len(errs), errs[:2])

    bulk_ok = 0
    bulk_errors = 0
    for start in range(0, len(update_actions), batch_size):
        chunk = update_actions[start: start + batch_size]
        ok, errs = bulk_write(es, docs_index, chunk)
        bulk_ok += ok
        bulk_errors += len(errs)
        if errs:
            log.warning("[%s] update errors (%d): %s", layer_label, len(errs), errs[:2])
        log.debug("[%s] Updated %d/%d docs", layer_label, start + len(chunk), n_docs)

    # Explicit refresh on both indexes we just wrote to. The mapping default
    # is refresh_interval=30s, which would otherwise leave a window where
    # the next pipeline step starts before ES has made the writes visible
    # — silently breaking the chain:
    #   cluster sessions -> name playbooks would find 0 centroids
    #   cluster commands -> escalate would find 0 commands with novelty
    #   cluster ips      -> any reader would see stale cluster.id values
    try:
        es.indices.refresh(index=f"{clusters_index},{docs_index}")
    except Exception as exc:
        log.warning("[%s] post-cluster refresh failed (continuing): %s", layer_label, exc)

    stats["docs_updated"] = bulk_ok
    stats["bulk_errors"] = bulk_errors
    stats["runtime_seconds"] = round(time.monotonic() - t_start, 2)
    stats["docs_index"] = docs_index
    stats["clusters_index"] = clusters_index
    return stats
