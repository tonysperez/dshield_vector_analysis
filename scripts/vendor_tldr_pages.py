#!/usr/bin/env python3
"""Fetch tldr-pages and bundle into a single JSON file for command grounding.

tldr-pages (https://tldr.sh/) is a community-maintained collection of short
example-driven cheat sheets for command-line tools, MIT-licensed. We use it
as the fallback `description` source for command grounding (ROADMAP #11);
curated YAML entries under `src/enrich/data/commands/curated/` take
precedence and supply structured per-flag descriptions.

Run whenever upstream pages are refreshed:

    python scripts/vendor_tldr_pages.py

Output: src/enrich/data/commands/tldr.json — a single JSON object
mapping `command_name` → `{os: summary_string, ...}`. One sub-entry per
OS section that documents the command, so cross-OS overlaps (e.g.
`ls` on Linux vs Windows PowerShell vs macOS BSD ls) all appear and
the LLM sees the variant for each platform tagged by name. Pages under
`pages/{common,linux,windows,osx,freebsd,cisco-ios}/` are included.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

SOURCE_URL = "https://github.com/tldr-pages/tldr/archive/refs/heads/main.tar.gz"
OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "src" / "enrich" / "data" / "commands" / "tldr.json"
)
# Subdirectories of tldr's `pages/` tree to include. Each accepted
# section becomes its own entry under the command's bundle key, so
# overlapping commands (`ls`, `cat`, `ping`, …) carry one summary per
# OS and the LLM sees the variant tagged by name. `common` is the
# cross-platform baseline; `linux` is the Cowrie-honeypot primary;
# `windows` / `osx` / `freebsd` / `cisco-ios` cover the platforms
# attackers may target laterally or fingerprint against.
ACCEPT_DIRS = ("common", "linux", "windows", "osx", "freebsd", "cisco-ios")
# Cap per-command, per-OS output so a verbose page can't blow up the JSON.
MAX_CHARS_PER_PAGE = 2000


def _extract_page(text: str) -> str:
    """Pull description + example block from a tldr Markdown page.

    Format (per tldr spec):
        # cmd
        \n
        > summary line 1
        > summary line 2
        \n
        - example description:
        \n
        `cmd arg {{placeholder}}`
        ...

    We keep the summary lines and the example descriptions, drop the
    code fences (the LLM doesn't need the exact `{{placeholder}}`
    syntax for grounding purposes).
    """
    out: list[str] = []
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s:
            continue
        if s.startswith("# "):
            continue                              # title — already implied by the key
        if s.startswith("> "):
            out.append(s[2:].strip())             # summary line
        elif s.startswith("- "):
            out.append(s[2:].rstrip(":").strip())  # example description
        # Lines starting with `\`` are code samples; skip.
    joined = " ".join(out).strip()
    if len(joined) > MAX_CHARS_PER_PAGE:
        joined = joined[:MAX_CHARS_PER_PAGE].rsplit(" ", 1)[0] + " ..."
    return joined


def main() -> int:
    print(f"Fetching {SOURCE_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(SOURCE_URL, timeout=120) as resp:
        data = resp.read()

    print(f"  downloaded {len(data) // 1024} KB", file=sys.stderr)

    # Outer dict keyed by command name; inner dict keyed by OS section.
    # No cross-section precedence — every OS's variant is preserved so the
    # block builder can surface each one tagged by name to the LLM.
    out: dict[str, dict[str, str]] = {}
    total_pages = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf:
            if not member.isfile() or not member.name.endswith(".md"):
                continue
            parts = member.name.split("/")
            # Expected layout: tldr-main/pages/{common,linux,...}/<cmd>.md
            try:
                pages_idx = parts.index("pages")
            except ValueError:
                continue
            if pages_idx + 2 >= len(parts):
                continue
            section = parts[pages_idx + 1]
            if section not in ACCEPT_DIRS:
                continue
            cmd_name = parts[pages_idx + 2].removesuffix(".md").lower()
            if not cmd_name:
                continue
            try:
                content = tf.extractfile(member).read().decode("utf-8", errors="replace")
            except Exception:
                continue
            summary = _extract_page(content)
            if not summary:
                continue
            out.setdefault(cmd_name, {})[section] = summary
            total_pages += 1

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Per-OS coverage stats for the operator.
    per_os = {os_name: 0 for os_name in ACCEPT_DIRS}
    for variants in out.values():
        for os_name in variants:
            per_os[os_name] = per_os.get(os_name, 0) + 1
    rel = OUTPUT.relative_to(Path(__file__).resolve().parents[1])
    print(
        f"  wrote {len(out)} distinct commands, {total_pages} per-OS pages to {rel}",
        file=sys.stderr,
    )
    for os_name in ACCEPT_DIRS:
        print(f"    {os_name:<10} {per_os.get(os_name, 0)} pages", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
