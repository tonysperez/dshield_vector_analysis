"""Command-grounding context for the local LLM (ROADMAP #11).

Builds a "COMMANDS REFERENCED" block that gets injected into the
command-enrichment prompt. For each command that appears in the shell
line being enriched, the block carries:

  - The curated description (if any) plus structured flag descriptions
    filtered to the flags actually present in the line.
  - One line per OS variant of the same command from tldr-pages —
    `cat (linux)`, `cat (windows)`, `cat (osx)`, etc. — so the LLM sees
    every platform's take on an overlapping name and can tell from
    context which one the attacker is invoking. Pure-overlap families
    (`ls`, `cat`, `ping`, `find`, etc.) all have multi-OS entries; the
    OS tag is what disambiguates them.

Data sources (curated wins on its own fields; tldr is *additive*, not
replaced):

  1. `src/enrich/data/commands/curated/<cmd>.yaml` — hand-curated,
     structured `{description, flags}`. Surfaces first with a
     `(curated)` tag.
  2. `src/enrich/data/commands/tldr.json` — vendored tldr-pages bundle.
     New shape (ROADMAP #11 follow-up): `{cmd: {os: summary, ...}}`.
     Each OS variant renders as its own block line tagged
     `(tldr/<os>)`. Produced by `scripts/vendor_tldr_pages.py` which
     pulls from `pages/{common,linux,windows,osx,freebsd,cisco-ios}/`.

The module loads everything once at import time. `_load_command_data`
is lazy and safe to call repeatedly.

The shell parser is heuristic — perfect shell parsing is undecidable
and attackers regularly do weird things. Soft-fail on unparseable
fragments: better to skip than to crash the enrichment pipeline.
"""
from __future__ import annotations

import json
import logging
import re
import shlex
from pathlib import Path
from typing import Optional

import yaml

log = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data" / "commands"
_CURATED_DIR = _DATA_DIR / "curated"
_TLDR_BUNDLE = _DATA_DIR / "tldr.json"

# Tokens that split a shell line into independent command segments.
# Includes `\n` for multi-line strings; conservative on background `&`
# (treats `&&` and `&` the same way — we don't need to model dependency,
# only segment boundaries).
_SEGMENT_SPLIT_RE = re.compile(r"\s*(?:\|\||&&|[|;&\n])\s*")

# Recognises a flag token — short (`-x`, `-xvf`) or long (`--no-check-certificate`).
_FLAG_RE = re.compile(r"^-{1,2}[A-Za-z][\w\-]*$")

# Subcommands that route through a multi-call binary; we treat the
# next non-flag, non-assignment token as the actual command to look up.
# `sudo` is intentionally NOT here — its flags can take arguments (`-u
# USER`, `-g GROUP`, `-D DIR`), so the next bare token after `sudo`
# isn't necessarily the wrapped command. The LLM still sees the full
# command text and can interpret `sudo … <cmd>` from context.
_MULTICALL_BINARIES = frozenset({"busybox"})


_loaded: Optional[dict[str, dict]] = None


def _load_command_data() -> dict[str, dict]:
    """Return the merged command data map.

    Entry shape per command:
      {
        "curated_description": str,      # "" when no curated entry
        "flags":               dict,     # {flag: description}; curated-only
        "tldr_by_os":          dict,     # {os: summary} for every OS that
                                         # documents this command in tldr-pages
        "source":              str,      # "curated" | "tldr" | "both" | "none"
      }

    Memoised. Loads both data sources on first access. The same dict
    object is returned on every subsequent call — callers must not
    mutate it. Cache invalidation lives in `compute_llm_config_hash`,
    which hashes the data directory's content.
    """
    global _loaded
    if _loaded is not None:
        return _loaded

    out: dict[str, dict] = {}

    # 1. tldr — keyed by command, then by OS. Backward-compatible with
    #    the older flat shape ({cmd: str}) for the rare case where the
    #    bundle hasn't been re-vendored yet — string values get wrapped
    #    into `{"common": str}`.
    if _TLDR_BUNDLE.exists():
        try:
            tldr = json.loads(_TLDR_BUNDLE.read_text(encoding="utf-8"))
            for cmd, body in tldr.items():
                cmd_lc = cmd.lower()
                if isinstance(body, dict):
                    variants = {
                        str(os_name).strip(): str(summary).strip()
                        for os_name, summary in body.items()
                        if os_name and isinstance(summary, str) and summary.strip()
                    }
                elif isinstance(body, str) and body.strip():
                    variants = {"common": body.strip()}
                else:
                    continue
                if variants:
                    out[cmd_lc] = {
                        "curated_description": "",
                        "flags": {},
                        "tldr_by_os": variants,
                        "source": "tldr",
                    }
        except Exception as exc:
            log.warning("could not load tldr bundle (%s): %s", _TLDR_BUNDLE, exc)

    # 2. Curated — overlays curated description + flags on top of any
    #    tldr variants. Curated description and tldr variants coexist;
    #    they both render in the prompt block, tagged differently.
    if _CURATED_DIR.exists():
        for yaml_path in sorted(_CURATED_DIR.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            except Exception as exc:
                log.warning("could not parse curated entry %s: %s", yaml_path, exc)
                continue
            cmd = yaml_path.stem.lower()
            description = (data.get("description") or "").strip()
            flags = {
                str(k).strip(): str(v).strip()
                for k, v in (data.get("flags") or {}).items()
                if k and v
            }
            if not description and not flags and cmd not in out:
                continue
            entry = out.get(cmd) or {
                "curated_description": "",
                "flags": {},
                "tldr_by_os": {},
                "source": "none",
            }
            entry["curated_description"] = description or entry["curated_description"]
            entry["flags"] = {**entry["flags"], **flags}
            entry["source"] = (
                "both" if entry["tldr_by_os"] else "curated"
            )
            out[cmd] = entry

    _loaded = out
    return out


def parse_shell_line(line: str) -> list[tuple[str, list[str]]]:
    """Return a list of (command, flags_present) tuples for each segment.

    Heuristic parser. Splits on shell separators, shlex.splits each
    segment, then:
      - first non-empty token in a segment that doesn't look like a
        variable assignment (`X=y`) is the command;
      - tokens matching `_FLAG_RE` are flags;
      - if the command is a multi-call binary (busybox / sudo), the
        next non-flag token is ALSO emitted as a command (so
        `busybox wget X` produces two entries: ("busybox", [...]) and
        ("wget", [...])).

    Soft-fails on unparseable segments by returning what it has so far.
    """
    if not line:
        return []
    out: list[tuple[str, list[str]]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    for segment in _SEGMENT_SPLIT_RE.split(line):
        segment = segment.strip()
        if not segment:
            continue
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            # Unbalanced quotes etc. — best-effort fallback to naive split.
            tokens = segment.split()
        if not tokens:
            continue

        # Skip leading env-var assignments `KEY=value` (common in shell).
        i = 0
        while i < len(tokens) and "=" in tokens[i] and not tokens[i].startswith("-"):
            i += 1
        if i >= len(tokens):
            continue

        cmd_token = tokens[i]
        # Strip leading path components: `./payload` → `payload`, `/usr/bin/wget` → `wget`.
        cmd_name = cmd_token.rsplit("/", 1)[-1].lstrip(".").lower()
        if not cmd_name or cmd_name.startswith("-"):
            continue

        flags = [t for t in tokens[i + 1:] if _FLAG_RE.match(t)]
        key = (cmd_name, tuple(sorted(flags)))
        if key not in seen:
            seen.add(key)
            out.append((cmd_name, flags))

        # Multi-call binaries: recurse one level for the subcommand.
        if cmd_name in _MULTICALL_BINARIES:
            for j in range(i + 1, len(tokens)):
                if not _FLAG_RE.match(tokens[j]) and "=" not in tokens[j]:
                    sub = tokens[j].rsplit("/", 1)[-1].lstrip(".").lower()
                    if sub:
                        sub_flags = [t for t in tokens[j + 1:] if _FLAG_RE.match(t)]
                        sub_key = (sub, tuple(sorted(sub_flags)))
                        if sub_key not in seen:
                            seen.add(sub_key)
                            out.append((sub, sub_flags))
                    break

    return out


# Preferred OS ordering when rendering tldr variants. `common` first
# because it's the cross-platform baseline; `linux` second because
# Cowrie is a Linux honeypot; rest in operational-relevance order.
_OS_ORDER = ("common", "linux", "windows", "osx", "freebsd", "cisco-ios")


def build_ground_truth_block(line: str, *, max_chars: int = 6000) -> str:
    """Render the COMMANDS REFERENCED block for one shell line.

    For each command found in the line:
      - `<cmd> (curated) — <curated description>` (when curated)
        followed by `<flag> <description>` lines for actually-present flags.
      - `<cmd> (tldr/<os>) — <variant summary>` once per OS that
        documents the command in tldr-pages.

    Cross-OS overlaps (`ls`, `cat`, `ping`, `find`, …) emit one block
    line per OS so the LLM can disambiguate from context which platform
    the attacker is on. The OS tag is what makes the duplication
    informative rather than noisy.

    Returns "(no recognized commands)" when nothing parsed or matched.
    Caps total output to `max_chars` so a pathological command line
    can't blow up the prompt.
    """
    parsed = parse_shell_line(line)
    if not parsed:
        return "(no recognized commands)"
    data = _load_command_data()

    out_lines: list[str] = []
    for cmd, flags in parsed:
        entry = data.get(cmd)
        if not entry:
            # Unknown command — still emit a line so the LLM knows we
            # tried, and so the Health page (ROADMAP #11.5) can count
            # this as a curation gap downstream.
            out_lines.append(f"  {cmd} — (no description available)")
            continue

        # Curated description first (no OS tag because curated entries
        # describe the command canonically across platforms).
        if entry.get("curated_description"):
            out_lines.append(
                f"  {cmd} (curated) — {entry['curated_description']}"
            )
            # Per-flag descriptions filtered to actually-present flags.
            if flags and entry.get("flags"):
                seen_flag_keys: set[str] = set()
                for f in flags:
                    if f in seen_flag_keys:
                        continue
                    seen_flag_keys.add(f)
                    desc = entry["flags"].get(f)
                    if desc:
                        out_lines.append(f"    {f}   {desc}")

        # Then one line per OS variant from tldr, ordered by _OS_ORDER
        # so the LLM sees the relevant baselines first.
        tldr_by_os = entry.get("tldr_by_os") or {}
        ordered_os = (
            [os_name for os_name in _OS_ORDER if os_name in tldr_by_os]
            + sorted(set(tldr_by_os) - set(_OS_ORDER))
        )
        for os_name in ordered_os:
            summary = tldr_by_os[os_name]
            out_lines.append(f"  {cmd} (tldr/{os_name}) — {summary}")

    block = "\n".join(out_lines)
    if len(block) > max_chars:
        # Truncate to the last full line that fits.
        block = block[:max_chars].rsplit("\n", 1)[0] + "\n  ... (truncated)"
    return block or "(no recognized commands)"


def reset_loaded_for_tests() -> None:
    """Test helper — drop the memoised data so a smoke test can override
    the data directory at runtime. Never called in production."""
    global _loaded
    _loaded = None


def list_known_commands() -> set[str]:
    """Return the set of all command names with a description loaded.

    Used by the (deferred) #11.5 Health page to compute the set-difference
    against commands actually seen in the corpus.
    """
    return set(_load_command_data().keys())
