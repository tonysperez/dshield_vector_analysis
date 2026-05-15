"""Health page backend — corpus-coverage status for command grounding.

ROADMAP #11.5. Walks the enriched-commands index, parses each
`process.command_line` via the shared
`enrich.command_grounding.parse_shell_line` (same heuristic the
enrichment prompt uses, so the page's coverage numbers match what the
LLM actually sees), classifies every command token against the loaded
grounding data, and returns ranked lists:

  - `needs_def`: commands seen in the corpus with NO entry anywhere.
    Top of this list is the natural next thing to hand-curate.
  - `tldr_only`: commands covered only by tldr-pages (no per-flag
    detail). Curating these adds analyst-relevant framing + flag
    descriptions.
  - `curated`: commands with a curated YAML entry. Just a count;
    surfaced as a coverage stat rather than a list.

This page is the first health surface in the console; future health
concerns will land here too.

The grounding module is in the parent `enrich` package — the import is
wrapped in a try/except so a console-only install (no pipeline)
degrades gracefully with `available: false`.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

log = logging.getLogger(__name__)

try:
    from enrich.command_grounding import (
        _load_command_data,
        add_to_denylist as _add_to_denylist,
        list_denied_commands,
        parse_shell_line,
        remove_from_denylist as _remove_from_denylist,
    )
    _GROUNDING_AVAILABLE = True
except Exception:                       # pragma: no cover — graceful degrade
    _GROUNDING_AVAILABLE = False


# Sample command lines per uncurated entry. Three feels like the right
# trade-off between "enough context to recognise the pattern" and "the
# JSON response stays small."
_SAMPLES_PER_CMD = 3
# Hard cap on the lists returned to the frontend so a runaway corpus
# can't blow up the response body. The lists are pre-sorted by count
# descending, so the highest-leverage entries are kept.
_MAX_LIST_LEN = 200


def health_commands(es, cfg, *, sample_limit: int = _SAMPLES_PER_CMD) -> dict[str, Any]:
    """Compute the command-coverage health report.

    Returns a dict with shape:

        {
          "available": bool,
          "stats": {
              "total_unique_cmds": int,
              "curated": int,
              "tldr_only": int,
              "needs_def": int,
              "total_corpus_occurrences": int,   # sum of all token counts
          },
          "needs_def": [{name, count, samples: [str]}, ...],
          "tldr_only": [{name, count, samples: [str]}, ...],
        }

    `needs_def` and `tldr_only` are each capped at `_MAX_LIST_LEN` and
    sorted by count descending. `curated` is intentionally omitted from
    the response body — it's the largest list and not actionable; the
    `stats.curated` count is the surfaced summary.
    """
    if not _GROUNDING_AVAILABLE:
        return {
            "available": False,
            "reason": (
                "`enrich.command_grounding` is not importable from this "
                "console install. Install the pipeline package "
                "(`pip install -e .` from the repo root) for command-"
                "coverage stats to populate."
            ),
        }

    data = _load_command_data()

    cmds_idx = cfg.elasticsearch.indexes.cowrie.commands
    body = {
        "size": 1000,
        "_source": [
            "process.command_line",
            "dshield.cowrie.enrichment.occurrence_count",
        ],
        "query": {"exists": {"field": "process.command_line"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }

    counts: dict[str, int] = defaultdict(int)
    samples: dict[str, list[str]] = defaultdict(list)
    total_corpus_occurrences = 0

    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=cmds_idx, **body)
        except Exception as exc:
            log.warning("health_commands ES search failed: %s", exc)
            break
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            src = h["_source"]
            cmd_line = (src.get("process") or {}).get("command_line") or ""
            if not cmd_line:
                continue
            # Weight each token by the command's occurrence_count when
            # available, so a single-occurrence one-off doesn't outrank a
            # cmd that appears in hundreds of events.
            occ = (
                ((src.get("dshield") or {}).get("cowrie", {}))
                .get("enrichment", {}).get("occurrence_count")
            ) or 1
            for cmd, _flags in parse_shell_line(cmd_line):
                counts[cmd] += int(occ)
                total_corpus_occurrences += int(occ)
                if len(samples[cmd]) < sample_limit and cmd_line not in samples[cmd]:
                    samples[cmd].append(cmd_line[:200])
        search_after = hits[-1]["sort"]

    denylist = list_denied_commands()

    needs_def: list[dict] = []
    tldr_only: list[dict] = []
    denied: list[dict] = []
    curated_count = 0
    for cmd, cnt in counts.items():
        item = {"name": cmd, "count": cnt, "samples": samples[cmd]}
        if cmd in denylist:
            item["rationale"] = denylist[cmd]
            denied.append(item)
            continue
        entry = data.get(cmd)
        if entry is None:
            needs_def.append(item)
        elif entry.get("curated_description"):
            curated_count += 1
        else:
            tldr_only.append(item)

    needs_def.sort(key=lambda x: -x["count"])
    tldr_only.sort(key=lambda x: -x["count"])
    denied.sort(key=lambda x: -x["count"])

    return {
        "available": True,
        "stats": {
            "total_unique_cmds": len(counts),
            "curated": curated_count,
            "tldr_only": len(tldr_only),
            "needs_def": len(needs_def),
            "denied": len(denied),
            "total_corpus_occurrences": total_corpus_occurrences,
        },
        "needs_def": needs_def[:_MAX_LIST_LEN],
        "tldr_only": tldr_only[:_MAX_LIST_LEN],
        "denied": denied[:_MAX_LIST_LEN],
    }


def add_token_to_denylist(token: str, rationale: str) -> tuple[bool, str]:
    """Thin pass-through to `enrich.command_grounding.add_to_denylist`,
    catching the unavailable-grounding case explicitly so the API can
    return a sane 503.
    """
    if not _GROUNDING_AVAILABLE:
        return False, "command grounding module not available on this install"
    return _add_to_denylist(token, rationale)


def remove_token_from_denylist(token: str) -> tuple[bool, str]:
    """Thin pass-through to `enrich.command_grounding.remove_from_denylist`."""
    if not _GROUNDING_AVAILABLE:
        return False, "command grounding module not available on this install"
    return _remove_from_denylist(token)
