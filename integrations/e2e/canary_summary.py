#!/usr/bin/env python3
"""Emit the framework-canary drift table (markdown, for $GITHUB_STEP_SUMMARY).

Usage: canary_summary.py <pinned-freeze.txt> <latest-freeze.txt>

``pinned-freeze.txt``  = ``pip list --format=freeze`` after installing the
adapter packages at their pyproject floors; ``latest-freeze.txt`` = the same
after ``pip install -U`` of the six frameworks. The table names, per
framework: the adapter's declared floor, the version the floors resolved to,
the unpinned-latest version the e2e suite just ran against, and whether it
drifted.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

INTEGRATIONS = Path(__file__).resolve().parent.parent

#: pip distribution name -> the adapter package that declares its floor.
FRAMEWORKS = {
    "llama-index-core": "verity-llamaindex",
    "langchain-core": "verity-langchain",
    "langgraph-checkpoint": "verity-langgraph",
    "crewai": "verity-crewai",
    "google-adk": "verity-adk",
    "openai-agents": "verity-openai-agents",
}


def parse_freeze(path: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    for line in Path(path).read_text().splitlines():
        if "==" in line:
            name, version = line.split("==", 1)
            versions[name.strip().lower()] = version.strip()
    return versions


def declared_floor(adapter: str, framework: str) -> str:
    pyproject = tomllib.loads((INTEGRATIONS / adapter / "pyproject.toml").read_text())
    for dep in pyproject["project"]["dependencies"]:
        requirement = dep.strip()
        match = re.match(rf"^{re.escape(framework)}\s*(.*)$", requirement)
        if match:
            return match.group(1).strip() or "(any)"
    return "(not declared)"


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    pinned = parse_freeze(sys.argv[1])
    latest = parse_freeze(sys.argv[2])

    drifted: list[str] = []
    rows: list[str] = []
    for framework, adapter in FRAMEWORKS.items():
        floor = declared_floor(adapter, framework)
        at_floor = pinned.get(framework, "(missing)")
        tested = latest.get(framework, "(missing)")
        moved = tested != at_floor
        if moved:
            drifted.append(f"{framework} {at_floor} -> {tested}")
        rows.append(
            f"| {framework} | `{floor}` | {at_floor} | {tested} | "
            f"{'**DRIFTED**' if moved else 'no'} |"
        )

    print("## Framework canary — version drift vs adapter floors\n")
    print("| framework | adapter floor | resolved at floor | latest (tested) | drift |")
    print("| --- | --- | --- | --- | --- |")
    print("\n".join(rows))
    print()
    if drifted:
        print(
            "Drifted since the floor-resolved install: **"
            + "**, **".join(drifted)
            + "** — the e2e run above executed against the drifted versions."
        )
    else:
        print("No framework drift: latest == floor-resolved for all six frameworks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
