"""ES bootstrap — apply project-owned templates and ingest pipelines.

Reads `setup/*.yaml` and `setup/es-pipelines/*.yml`, each formatted as a
Kibana DevTools snippet:

    PUT _index_template/prism.raw
    {
      "index_patterns": [...],
      ...
    }

Sends each via the project's existing ES client (same TLS / auth model
as everything else). Idempotent: any PUT on an existing template /
pipeline overwrites it.

Called by `dshield_prism bootstrap-es` and by the setup script so a
fresh node has the data-stream template + ingest pipelines in place
before any cowrie events flow.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable

from .config import AppConfig, Secrets
from .es_client import make_client

log = logging.getLogger(__name__)


# Files we ship. Globbed at runtime; missing files are skipped (the
# template is optional — operators who want a plain index can delete
# it and bootstrap-es will just skip it).
_BOOTSTRAP_GLOBS: tuple[str, ...] = (
    "setup/*.yaml",
    "setup/*.yml",
    "setup/es-pipelines/*.yaml",
    "setup/es-pipelines/*.yml",
)


def _parse_devtools_snippet(text: str, path: Path) -> tuple[str, str, dict]:
    """Parse a Kibana DevTools-style snippet into (method, api_path, body).

    Format:
        <METHOD> <api_path>
        {
          ... JSON body ...
        }

    Whitespace + trailing newlines are tolerant. Comments aren't
    supported on the first line — keep it bare.
    """
    stripped = text.lstrip()
    if not stripped:
        raise ValueError(f"{path}: empty file")
    first_newline = stripped.find("\n")
    if first_newline < 0:
        raise ValueError(f"{path}: missing body (no newline after METHOD PATH)")
    header = stripped[:first_newline].strip()
    body_text = stripped[first_newline + 1:].strip()

    parts = header.split(None, 1)
    if len(parts) != 2:
        raise ValueError(
            f"{path}: first line must be `METHOD PATH` "
            f"(got: {header!r})"
        )
    method, api_path = parts[0].upper(), parts[1]
    if method not in ("PUT", "POST", "DELETE"):
        raise ValueError(f"{path}: unsupported method {method!r}")
    try:
        body = json.loads(body_text) if body_text else {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: body is not valid JSON: {exc}") from exc
    return method, api_path, body


def _apply_priority(api_path: str) -> int:
    """Sort key for bootstrap files. Lower = applied earlier.

    Order matters: an index template must exist BEFORE the data stream
    it shapes is created, or the data stream falls back to cluster
    defaults. Pipelines can land any time but conventionally precede
    data-stream creation so an immediate write is normalised correctly.
    """
    p = api_path.lstrip("/")
    if p.startswith("_component_template/") or p.startswith("_index_template/"):
        return 1
    if p.startswith("_ilm/policy/"):
        return 2
    if p.startswith("_ingest/pipeline/"):
        return 3
    if p.startswith("_data_stream/"):
        return 4
    return 5


def _iter_bootstrap_files(repo_root: Path) -> Iterable[Path]:
    """Yield every file matching the bootstrap globs. Filesystem
    alphabetic order doesn't put templates before data streams (the
    `prism.raw.*` files sort the wrong way around), so resource-type
    priority is applied later in `run_bootstrap` once each file's
    header has been parsed.
    """
    seen: set[Path] = set()
    for pattern in _BOOTSTRAP_GLOBS:
        for p in sorted(repo_root.glob(pattern)):
            if p not in seen:
                seen.add(p)
                yield p


def run_bootstrap(
    cfg: AppConfig, secrets: Secrets, *,
    repo_root: Path | None = None, dry_run: bool = False,
) -> dict:
    """Apply every bootstrap file to ES. Returns a stats dict.

    `repo_root` defaults to the current working directory — the setup
    script and the CLI both run from the install dir, where the
    `setup/` tree lives.
    """
    root = (repo_root or Path.cwd()).resolve()
    files = list(_iter_bootstrap_files(root))
    if not files:
        log.warning("bootstrap-es: no files found under %s/setup/", root)
        return {"applied": 0, "files": [], "dry_run": dry_run}

    # Parse every file up front so we can reorder by resource type
    # before sending anything. A file whose first line fails to parse
    # is reported but doesn't block the rest.
    parsed: list[tuple[Path, str, str, dict]] = []
    parse_errors: list[dict] = []
    for f in files:
        try:
            method, api_path, body = _parse_devtools_snippet(f.read_text(), f)
            parsed.append((f, method, api_path, body))
        except ValueError as exc:
            parse_errors.append({"file": str(f), "error": str(exc)})
            log.error("bootstrap-es: %s", exc)

    # Stable sort by (priority, filename) — templates before data
    # streams, etc.; alphabetic within each priority bucket.
    parsed.sort(key=lambda t: (_apply_priority(t[2]), str(t[0])))

    es = None if dry_run else make_client(cfg.elasticsearch, secrets)
    applied: list[dict] = []
    errors: list[dict] = list(parse_errors)

    for f, method, api_path, body in parsed:
        entry = {
            "file": str(f.relative_to(root)),
            "method": method,
            "path": api_path,
        }
        if dry_run:
            entry["action"] = "would_apply"
            applied.append(entry)
            continue
        try:
            # perform_request lets us speak the same generic DevTools
            # shape regardless of resource type (index template, ingest
            # pipeline, ILM policy, etc.) without hardcoding endpoints.
            #
            # Bodyless requests like `PUT _data_stream/<name>` reject an
            # empty `{}` body (ES treats `{}` as a malformed payload for
            # endpoints that expect none). Send None in that case so the
            # transport omits the body entirely.
            request_body = body if body else None
            # elastic_transport doesn't auto-set Content-Type when calling
            # perform_request at this low level — the higher-level helpers
            # (es.indices.*, es.ingest.*) do, but here we're generic.
            # Always send JSON; Accept covers the response decoding too.
            req_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            resp = es.perform_request(
                method, "/" + api_path.lstrip("/"),
                body=request_body, headers=req_headers,
            )
            ack = bool((resp.body or {}).get("acknowledged", True)) if hasattr(resp, "body") else True
            entry["acknowledged"] = ack
            entry["action"] = "applied"
            applied.append(entry)
            log.info("bootstrap-es: %s %s → ack=%s", method, api_path, ack)
        except Exception as exc:
            # Idempotency: `PUT _data_stream/<name>` raises 400
            # resource_already_exists_exception on re-run. Treat that as
            # a no-op so re-running setup.sh is safe. Templates and
            # ingest pipelines are natively idempotent (PUT overwrites)
            # so they never hit this branch.
            msg = str(exc)
            if "resource_already_exists_exception" in msg or "already exists" in msg.lower():
                entry["action"] = "exists"
                entry["acknowledged"] = True
                applied.append(entry)
                log.info("bootstrap-es: %s %s → already exists (no-op)", method, api_path)
                continue
            entry["action"] = "failed"
            entry["error"] = str(exc)
            errors.append(entry)
            log.error("bootstrap-es: %s %s failed: %s", method, api_path, exc)

    return {
        "applied": sum(1 for e in applied if e.get("action") == "applied"),
        "skipped_dry_run": sum(1 for e in applied if e.get("action") == "would_apply"),
        "errors": errors,
        "files": applied,
        "dry_run": dry_run,
    }
