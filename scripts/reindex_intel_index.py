"""One-shot reindex helper for intel-*-default indices.

Use when an additive `init-indexes --update-mapping` fails because the
existing index has dynamic-inferred field types that conflict with
the explicit mapping (the M2 deploy gotcha: greynoise/abuseipdb
string fields got auto-mapped as `text+keyword` before the explicit
mapping landed, and ES then refuses to retype them as plain
`keyword`).

Strategy: temp-index reindex preserves the canonical name and all
doc data — same idea as Kibana's recipe, codified so it runs from
the CLI with proper status checks and rollback hints.

Steps:
    1. Validate the source index exists and the on-disk mapping file
       is valid JSON.
    2. Create `<source>-reindex-tmp` using the on-disk mapping.
    3. Reindex source → temp (waits for completion via the task API
       so the script doesn't return before ES finishes).
    4. Verify doc counts match.
    5. Delete source.
    6. Create source with the on-disk mapping.
    7. Reindex temp → source.
    8. Verify counts match.
    9. Delete temp.

Halts and prints a recovery hint on any failure. The temp index is
*not* automatically deleted on failure so you can hand-finish the
recovery in Kibana Dev Tools without losing data.

Run from the install root (e.g. /opt/dshield_prism). Defaults to
`--source intel --layer ip`. Requires the same .env / config as the
pipeline.

Usage:
    sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python \\
      scripts/reindex_intel_index.py --dry-run
    sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python \\
      scripts/reindex_intel_index.py --yes
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.cli import _LAYER_MAPPINGS, _resolve_index_for_layer
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client


# Settings the user is likely to want surfaced.
_DEFAULT_SOURCE = "intel"
_DEFAULT_LAYER = "ip"
# How long to wait between polling the reindex task for completion.
_POLL_SECONDS = 5.0
# Hard ceiling on how long to wait for one reindex; bail with a clear
# error if exceeded so the script never hangs forever on a stuck task.
_MAX_WAIT_SECONDS = 3600.0


def fatal(msg: str, hint: str = "") -> None:
    print(f"\n[FATAL] {msg}", file=sys.stderr)
    if hint:
        print(f"        hint: {hint}", file=sys.stderr)
    sys.exit(1)


def info(msg: str) -> None:
    print(f"[..] {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"[ok] {msg}", flush=True)


def _load_mapping_body(mapping_path: str) -> dict[str, Any]:
    """Read the mapping JSON; strip leading-underscore comment keys."""
    raw = json.loads(Path(mapping_path).read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def _wait_for_reindex(es, task_id: str, label: str) -> dict[str, Any]:
    """Block until the reindex task finishes. Returns the final task body."""
    info(f"polling reindex task {task_id} ({label}) every {_POLL_SECONDS}s...")
    deadline = time.monotonic() + _MAX_WAIT_SECONDS
    while True:
        try:
            t = es.tasks.get(task_id=task_id)
        except Exception as exc:
            fatal(f"failed to poll task {task_id}: {exc}")
        if t.get("completed"):
            failures = (t.get("response") or {}).get("failures") or []
            if failures:
                print(
                    f"[FATAL] reindex task {task_id} completed with "
                    f"{len(failures)} per-doc failures:",
                    file=sys.stderr,
                )
                for f in failures[:5]:
                    print(f"        {f}", file=sys.stderr)
                if len(failures) > 5:
                    print(
                        f"        … {len(failures) - 5} more",
                        file=sys.stderr,
                    )
                fatal(
                    "reindex had failures; not safe to continue",
                    hint=(
                        "Inspect the temp index in Kibana; once any "
                        "fixable issues are resolved, you can re-run "
                        "this script or finish in Dev Tools."
                    ),
                )
            return t
        status = (t.get("task") or {}).get("status") or {}
        created = status.get("created", "?")
        total = status.get("total", "?")
        info(f"  {label}: created={created}/{total}")
        if time.monotonic() > deadline:
            fatal(
                f"reindex task {task_id} exceeded {_MAX_WAIT_SECONDS}s, "
                "still running",
                hint=(
                    f"Task is still in-flight — check `GET /_tasks/{task_id}` "
                    "in Kibana. Don't re-run this script until it completes."
                ),
            )
        time.sleep(_POLL_SECONDS)


def _reindex(es, source: str, dest: str, label: str) -> None:
    """Submit an async reindex and block for completion via the task API."""
    info(f"reindex {source} → {dest} ({label})")
    try:
        resp = es.reindex(
            wait_for_completion=False,
            body={"source": {"index": source}, "dest": {"index": dest}},
        )
    except Exception as exc:
        fatal(f"reindex submit failed: {exc}")
    task_id = resp.get("task")
    if not task_id:
        fatal(f"reindex submit returned no task id: {resp}")
    _wait_for_reindex(es, task_id, label)
    # Refresh the destination so the count check sees the new docs.
    try:
        es.indices.refresh(index=dest)
    except Exception as exc:
        info(f"refresh {dest} failed (continuing): {exc}")


def _doc_count(es, index: str) -> int:
    r = es.count(index=index)
    return int(r["count"])


def _assert_counts_match(es, a: str, b: str) -> None:
    ca, cb = _doc_count(es, a), _doc_count(es, b)
    if ca != cb:
        fatal(
            f"doc count mismatch: {a}={ca} vs {b}={cb}",
            hint=(
                f"Temp index {b} (or {a}) has been left in place — "
                "investigate the diff before continuing manually."
            ),
        )
    ok(f"doc counts match: {a} = {b} = {ca}")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--config", default=None, help="Path to YAML config (default: env)")
    p.add_argument("--source", default=_DEFAULT_SOURCE,
                   help="Source name (default: intel)")
    p.add_argument("--layer", default=_DEFAULT_LAYER,
                   help="Layer name (default: ip)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the plan and exit; do not modify ES")
    p.add_argument("--yes", action="store_true",
                   help="Skip the destructive-action confirmation prompt")
    return p.parse_args()


def main() -> int:
    args = _parse_args()

    cfg = load_config(args.config)
    secrets = load_secrets(args.config)

    mappings = _LAYER_MAPPINGS.get(args.source)
    if mappings is None:
        fatal(f"unknown source: {args.source!r}",
              hint=f"valid: {sorted(_LAYER_MAPPINGS)}")
    mapping_path = mappings.get(args.layer)
    if not mapping_path:
        fatal(
            f"unknown layer {args.layer!r} for source {args.source!r}",
            hint=f"valid layers: {sorted(mappings)}",
        )
    mapping_body = _load_mapping_body(mapping_path)
    source_index = _resolve_index_for_layer(cfg, args.source, args.layer)
    temp_index = f"{source_index}-reindex-tmp"

    es = make_client(cfg.elasticsearch, secrets)

    info(f"source index : {source_index}")
    info(f"temp index   : {temp_index}")
    info(f"mapping file : {mapping_path}")

    if not es.indices.exists(index=source_index):
        fatal(f"source index does not exist: {source_index}")

    src_count = _doc_count(es, source_index)
    info(f"source has {src_count} docs")

    if es.indices.exists(index=temp_index):
        fatal(
            f"temp index {temp_index} already exists",
            hint=(
                "A previous reindex was interrupted. Inspect it in "
                "Kibana, decide whether to keep it or DELETE it, then "
                "re-run this script."
            ),
        )

    if args.dry_run:
        print("\n[DRY-RUN] would:")
        print(f"  1. PUT    /{temp_index}                  (new mapping)")
        print(f"  2. POST   /_reindex   {source_index} → {temp_index}")
        print(f"  3. DELETE /{source_index}")
        print(f"  4. PUT    /{source_index}                (new mapping)")
        print(f"  5. POST   /_reindex   {temp_index} → {source_index}")
        print(f"  6. DELETE /{temp_index}")
        print(f"\n  Expected to preserve all {src_count} docs.")
        return 0

    if not args.yes:
        print(
            "\n  This will DELETE and recreate "
            f"`{source_index}`. The temp index `{temp_index}` will "
            "hold a copy of the data throughout, so the operation is "
            "recoverable — but if anything fails, you'll need to "
            "finish in Kibana Dev Tools manually.\n"
        )
        try:
            resp = input(f"  Proceed? [y/N] ").strip().lower()
        except EOFError:
            resp = ""
        if resp not in ("y", "yes"):
            print("Aborted.")
            return 1

    # 1. Create temp with new mapping
    info(f"creating temp index {temp_index}")
    try:
        es.indices.create(index=temp_index, **mapping_body)
    except Exception as exc:
        fatal(f"failed to create temp index: {exc}")
    ok(f"created {temp_index}")

    # 2. Reindex source → temp
    _reindex(es, source_index, temp_index, "forward")
    _assert_counts_match(es, source_index, temp_index)

    # 3. Delete source
    info(f"deleting source index {source_index}")
    try:
        es.indices.delete(index=source_index)
    except Exception as exc:
        fatal(
            f"failed to delete source index: {exc}",
            hint=(
                f"Data is safe in {temp_index}. Delete {source_index} "
                f"manually (DELETE /{source_index}) and re-run the "
                "remaining steps in Kibana, or fix permissions and "
                "re-run this script."
            ),
        )
    ok(f"deleted {source_index}")

    # 4. Recreate source with new mapping
    info(f"recreating {source_index} with new mapping")
    try:
        es.indices.create(index=source_index, **mapping_body)
    except Exception as exc:
        fatal(
            f"failed to recreate source index: {exc}",
            hint=(
                f"Data is still safe in {temp_index}. Create "
                f"{source_index} manually with the new mapping, then "
                "reindex from temp."
            ),
        )
    ok(f"created {source_index}")

    # 5. Reindex temp → source
    _reindex(es, temp_index, source_index, "back-fill")
    _assert_counts_match(es, source_index, temp_index)

    # 6. Delete temp
    info(f"deleting temp index {temp_index}")
    try:
        es.indices.delete(index=temp_index)
    except Exception as exc:
        # Non-fatal: source is restored, temp is orphan but data is safe.
        print(
            f"\n[warn] failed to delete temp index {temp_index}: {exc}\n"
            f"       Source index {source_index} is restored with full data.\n"
            f"       Delete the temp index manually when convenient: "
            f"DELETE /{temp_index}\n",
            file=sys.stderr,
        )
    else:
        ok(f"deleted {temp_index}")

    final = _doc_count(es, source_index)
    print(
        f"\n[done] {source_index} reindexed: {src_count} → {final} docs. "
        "Next: `intel reapply-rules`."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
