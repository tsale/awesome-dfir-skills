#!/usr/bin/env python3
"""Validate skill files in ./skills.

This is intentionally dependency-free (standard library only).

Checks:
- skill.md exists under skills/<category>/<skill-id>/
- YAML-ish frontmatter exists (--- ... ---)
- required keys exist in frontmatter

Exit codes:
- 0: OK
- 1: validation failures
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


REQUIRED_KEYS = {
    "name",
    "description"
}


@dataclass
class Problem:
    path: Path
    message: str


def find_skill_markdowns(skills_dir: Path) -> List[Path]:
    results: List[Path] = []
    for root, dirs, files in os.walk(skills_dir):
        # Skip templates
        if Path(root).parts[-1] == "_templates":
            dirs[:] = []
            continue
        # Case-insensitive search for skill.md
        for file in files:
            if file.lower() == "skill.md":
                results.append(Path(root) / file)
                break
    return sorted(results)


def parse_frontmatter(text: str) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """Parse very small subset of YAML frontmatter.

    We only need to know which top-level keys exist.
    """

    if not text.startswith("---\n"):
        return None, "missing frontmatter opening ---"

    end = text.find("\n---\n", 4)
    if end == -1:
        return None, "missing frontmatter closing ---"

    block = text[4:end]
    keys: Dict[str, str] = {}

    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # top-level key: value
        if re.match(r"^[A-Za-z0-9_-]+\s*:", line):
            k = line.split(":", 1)[0].strip()
            keys[k] = "1"

    return keys, None


def validate_skill_path(path: Path) -> List[Problem]:
    problems: List[Problem] = []

    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        return [Problem(path, f"cannot read file: {e}")]

    keys, err = parse_frontmatter(text)
    if err:
        problems.append(Problem(path, err))
        return problems

    missing = sorted(REQUIRED_KEYS - set(keys or {}))
    if missing:
        problems.append(Problem(path, f"missing frontmatter keys: {', '.join(missing)}"))

    # Ensure skill location is skills/<category>/<skill-id>/skill.md
    parts = path.parts
    try:
        idx = parts.index("skills")
        rel = parts[idx:]
    except ValueError:
        rel = path.parts

    if len(rel) < 4 or rel[-1].lower() != "skill.md":
        problems.append(Problem(path, "unexpected location; expected skills/<category>/<skill-id>/skill.md"))

    return problems


def main(argv: List[str]) -> int:
    root = Path(__file__).resolve().parent
    skills_dir = root / "skills"

    if not skills_dir.exists():
        print("ERROR: skills/ directory not found", file=sys.stderr)
        return 1

    skill_files = find_skill_markdowns(skills_dir)
    if not skill_files:
        print("ERROR: no skill.md files found under skills/", file=sys.stderr)
        return 1

    print(f"Checking {len(skill_files)} skill(s):")
    for p in skill_files:
        print(f"  - {p.relative_to(root)}")
    print()

    problems: List[Problem] = []
    for p in skill_files:
        problems.extend(validate_skill_path(p))

    if problems:
        print(f"Found {len(problems)} problem(s):")
        for prob in problems:
            print(f"- {prob.path.relative_to(root)}: {prob.message}")
        return 1

    print(f"OK: validated {len(skill_files)} skill(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
