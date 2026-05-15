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
_DENYLIST_PATH = _DATA_DIR / "denylist.yaml"

# Shell tokens that separate independent command segments. We
# tokenize the line via shlex FIRST (which respects quotes), then
# split on these as separator tokens — so the contents of quoted
# strings like `awk '{print $4;$5}'` or `echo "foo; bar"` no longer
# fragment the parse into spurious "commands."
_SHELL_SEPARATORS = frozenset({";", "|", "&", "&&", "||", "\n"})

# Recognises a flag token — short (`-x`, `-xvf`) or long (`--no-check-certificate`).
_FLAG_RE = re.compile(r"^-{1,2}[A-Za-z][\w\-]*$")

# Strict whitelist for command names. A real command starts with a
# letter, then letters / digits / `_` / `.` / `-`, length-capped to
# avoid soaking up large blobs. Filters parser noise that previously
# leaked into the corpus-coverage Health page (ROADMAP #11.5): tokens
# like `}'`, `accept-encoding:`, `6`, `` `'8 ``, `}" `, etc.
_VALID_CMD_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

# Subcommands that route through a multi-call binary; we treat the
# next non-flag, non-assignment token as the actual command to look up.
# `sudo` is intentionally NOT here — its flags can take arguments (`-u
# USER`, `-g GROUP`, `-D DIR`), so the next bare token after `sudo`
# isn't necessarily the wrapped command. The LLM still sees the full
# command text and can interpret `sudo … <cmd>` from context.
_MULTICALL_BINARIES = frozenset({"busybox"})


_loaded: Optional[dict[str, dict]] = None
_loaded_denylist: Optional[dict[str, str]] = None


def _load_denylist() -> dict[str, str]:
    """Return `{token_lowercase: rationale}` from `denylist.yaml`.

    Tokens listed here are suppressed from the LLM grounding block
    (they're attacker-named payload binaries, prompt leakage, etc., not
    real commands) and bucketed separately on the Health page. Edits
    propagate via the cache hash. Memoised.
    """
    global _loaded_denylist
    if _loaded_denylist is not None:
        return _loaded_denylist
    out: dict[str, str] = {}
    if _DENYLIST_PATH.exists():
        try:
            raw = yaml.safe_load(_DENYLIST_PATH.read_text(encoding="utf-8")) or {}
            for token, rationale in raw.items():
                if not token:
                    continue
                out[str(token).strip().lower()] = str(rationale or "").strip()
        except Exception as exc:
            log.warning("could not load denylist (%s): %s", _DENYLIST_PATH, exc)
    _loaded_denylist = out
    return out


def list_denied_commands() -> dict[str, str]:
    """Public accessor — used by the Health page (ROADMAP #11.5) to
    bucket denied tokens separately from `needs_def`."""
    return dict(_load_denylist())


# Header that gets prepended to every denylist.yaml write. The file is
# rewritten in full on each mutation (sorted entries), so user-added
# comments inside the file body are NOT preserved across edits — that's
# the trade-off for a simple, deterministic writer. Edit this header
# string here if the wording needs to change.
_DENYLIST_HEADER = """# Tokens that the shell parser surfaces as "commands" but are actually
# attacker-named payload binaries, prompt leakage, or other artifacts.
# The Health page (ROADMAP #11.5) buckets these as `denied` rather
# than `needs_def`, and the LLM grounding block omits them entirely
# (they'd just be noise in the prompt).
#
# Format: `<token>: "<one-line rationale>"`.
# Edited via the Health page's block/unblock buttons or by hand.
# The cache-hash machinery picks the file up automatically; any
# affected cached enrichments get re-LLM'd on the next backward firing.
#
# Token comparison is case-insensitive — the parser lowercases before
# lookup, so entries are stored in lowercase.
"""


def _normalise_token(token: str) -> str:
    """Lowercase + strip, with mild validation. Returns "" on rejected input.

    Permissive enough for hand-additions of edge cases the strict shell
    parser wouldn't surface (e.g. HTTP-header-shaped tokens like
    `accept-encoding:`) but rejects anything that would break the YAML
    round-trip (whitespace, newlines, quote chars, backslashes) or that
    looks obviously wrong (empty, overlong).
    """
    t = (token or "").strip().lower()
    if not t or len(t) > 64:
        return ""
    if any(c.isspace() or c in "\"'\\" for c in t):
        return ""
    return t


def _write_denylist(entries: dict[str, str]) -> None:
    """Atomically rewrite the denylist file with `entries`.

    Sorts keys for deterministic diffs. Writes to a sibling temp file
    and renames into place so a partial write can't leave the file
    corrupted (and so the rename is atomic on POSIX, no read-during-
    write race with `_load_denylist`). Clears the memoised denylist
    cache so the next read sees the new contents.
    """
    _DENYLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [_DENYLIST_HEADER, ""]
    if not entries:
        lines.append("# (no entries — denylist is empty)")
    else:
        for token in sorted(entries):
            rationale = entries[token].replace('"', '\\"').strip()
            lines.append(f'"{token}": "{rationale}"')
    content = "\n".join(lines) + "\n"

    tmp = _DENYLIST_PATH.with_suffix(_DENYLIST_PATH.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(_DENYLIST_PATH)

    # Drop the memoised cache so the next call re-reads.
    global _loaded_denylist
    _loaded_denylist = None


def add_to_denylist(token: str, rationale: str) -> tuple[bool, str]:
    """Insert (token → rationale) into the denylist. Returns (ok, message).

    Rejects whitespace-bearing or otherwise malformed tokens. If the
    token already exists, the rationale is updated (last-write-wins).
    `rationale` is truncated to 300 chars.
    """
    norm = _normalise_token(token)
    if not norm:
        return False, f"rejected token (whitespace or invalid characters): {token!r}"
    rationale = (rationale or "").strip()[:300]
    entries = dict(_load_denylist())
    entries[norm] = rationale or f"added via Health page (no rationale supplied)"
    _write_denylist(entries)
    return True, f"added {norm!r} to denylist"


def remove_from_denylist(token: str) -> tuple[bool, str]:
    """Remove `token` from the denylist. Returns (ok, message).

    Returns False if the token isn't present (caller should treat as a
    no-op rather than an error in most cases).
    """
    norm = _normalise_token(token)
    if not norm:
        return False, f"rejected token (whitespace or invalid characters): {token!r}"
    entries = dict(_load_denylist())
    if norm not in entries:
        return False, f"{norm!r} not in denylist"
    del entries[norm]
    _write_denylist(entries)
    return True, f"removed {norm!r} from denylist"


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


def _split_shell_segments(line: str) -> list[list[str]]:
    """Tokenize the line with shlex (quote-aware), then split into
    segments on unquoted shell operators.

    Returns a list of token lists, one per shell-segment, with the
    operator tokens themselves removed. Quoted regions stay intact as
    single tokens — so `echo "a; b" | sh` → `[["echo", "a; b"], ["sh"]]`
    rather than slicing the quoted block.

    Falls back to whitespace-split on unbalanced quotes so attacker
    weirdness doesn't crash the parser.
    """
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        tokens = line.split()
    segments: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok in _SHELL_SEPARATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


def _command_name_from_token(token: str) -> str:
    """Extract a candidate command name from a token.

    Strips leading path components (`./payload` → `payload`,
    `/usr/bin/wget` → `wget`) and any leading `.`. Returns the empty
    string if the result doesn't look like a real command name
    (`_VALID_CMD_NAME_RE`).
    """
    raw = token.rsplit("/", 1)[-1].lstrip(".").lower()
    return raw if _VALID_CMD_NAME_RE.match(raw) else ""


def parse_shell_line(line: str) -> list[tuple[str, list[str]]]:
    """Return a list of (command, flags_present) tuples for each segment.

    Quote-aware. Tokenizes the line via shlex first, then segments on
    unquoted shell operators (`;|&&||&\\n`). Each segment's first
    non-assignment token is the command; subsequent `-x`-style tokens
    are its flags. The command name is validated by `_VALID_CMD_NAME_RE`
    so parser noise (quoted-string fragments, HTTP-header tokens, bare
    numbers, etc.) doesn't bleed into the result.

    Multi-call binaries (`busybox`) emit both the binary and its
    sub-command.

    Soft-fails on any segment that doesn't yield a valid command.
    """
    if not line:
        return []
    out: list[tuple[str, list[str]]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    for tokens in _split_shell_segments(line):
        if not tokens:
            continue

        # Skip leading env-var assignments `KEY=value` (common in shell).
        i = 0
        while i < len(tokens) and "=" in tokens[i] and not tokens[i].startswith("-"):
            i += 1
        if i >= len(tokens):
            continue

        cmd_name = _command_name_from_token(tokens[i])
        if not cmd_name:
            continue

        flags = [t for t in tokens[i + 1:] if _FLAG_RE.match(t)]
        key = (cmd_name, tuple(sorted(flags)))
        if key not in seen:
            seen.add(key)
            out.append((cmd_name, flags))

        # Multi-call binaries: recurse one level for the subcommand.
        if cmd_name in _MULTICALL_BINARIES:
            for j in range(i + 1, len(tokens)):
                if _FLAG_RE.match(tokens[j]) or "=" in tokens[j]:
                    continue
                sub = _command_name_from_token(tokens[j])
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
    denylist = _load_denylist()

    out_lines: list[str] = []
    for cmd, flags in parsed:
        # Denylisted tokens are attacker-named payloads / prompt
        # leakage / etc. — emitting them as "(no description
        # available)" would just be noise in the prompt. Skip silently.
        if cmd in denylist:
            continue
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
    global _loaded, _loaded_denylist
    _loaded = None
    _loaded_denylist = None


def list_known_commands() -> set[str]:
    """Return the set of all command names with a description loaded.

    Used by the (deferred) #11.5 Health page to compute the set-difference
    against commands actually seen in the corpus.
    """
    return set(_load_command_data().keys())
