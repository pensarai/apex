#!/usr/bin/env python3
"""Encode bash-collected profile data as JSON.

Reads newline-delimited buckets from stdin, with `---NAME---` markers
between sections. Reads CODEBASE / GIT_SHA / GIT_BRANCH / GIT_REMOTE
from the environment. Also reads package.json scripts for build/test
hints. Emits a single JSON object on stdout.
"""

from __future__ import annotations

import json
import os
import sys


def parse_buckets(raw: list[str]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {}
    current: str | None = None
    for line in raw:
        if line.startswith("---") and line.endswith("---"):
            name = line.strip("- ")
            if name == "END":
                break
            current = name
            buckets[current] = []
            continue
        if current is not None and line:
            buckets[current].append(line)
    return buckets


def extract_pkg_scripts(codebase: str) -> tuple[str, str]:
    pkg = os.path.join(codebase, "package.json")
    if not os.path.isfile(pkg):
        return ("", "")
    try:
        with open(pkg) as f:
            data = json.load(f)
    except Exception:
        return ("", "")
    if not isinstance(data, dict):
        return ("", "")
    scripts = data.get("scripts") or {}
    if not isinstance(scripts, dict):
        return ("", "")
    return (scripts.get("build", "") or "", scripts.get("test", "") or "")


def main() -> None:
    raw = sys.stdin.read().splitlines()
    buckets = parse_buckets(raw)
    codebase = os.environ.get("CODEBASE", "")
    build_hint, test_hint = extract_pkg_scripts(codebase)
    out = {
        "path": codebase,
        "languages": buckets.get("LANGS", []),
        "packageManagers": buckets.get("PKG_MGRS", []),
        "lockfiles": buckets.get("LOCKFILES", []),
        "build": build_hint,
        "test": test_hint,
        "installedScanners": buckets.get("SCANNERS", []),
        "entryPoints": buckets.get("ENTRYPOINTS", []),
        "git": {
            "sha": os.environ.get("GIT_SHA", ""),
            "branch": os.environ.get("GIT_BRANCH", ""),
            "remote": os.environ.get("GIT_REMOTE", ""),
        },
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
