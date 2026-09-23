#!/usr/bin/env python3
"""
Version consistency gate.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026

Always: every "Version:" header in the repository equals pyproject's
project.version (they drifted before — opensc-test-almaz.ps1 said 0.27 while
everything else said 0.30).

With --tag vX.Y (release.yml, on a tag push): the tag equals project.version
and CHANGELOG.md has a released "## vX.Y" section. Without this gate, tagging
v0.31 while pyproject still said 0.30 produced release assets named 0.31 and a
wheel / `pip show` reporting 0.30, and a "— unreleased" section shipped as
release notes.

    python scripts/check_version.py              # header consistency
    python scripts/check_version.py --tag v0.31  # + release gate
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# "Version:  0.30" in module docstrings / doc header blocks, "# Version:  0.30"
# in the PowerShell script (which is CP1251, hence the byte-level read).
_HEADER_RE = re.compile(rb"^(?:# )?Version: +(\d+\.\d+(?:\.\d+)?)\s*$", re.MULTILINE)
_SKIP_DIRS = {".git", "node_modules", "build", "dist", "downloads", ".venv", "venv"}
_SUFFIXES = {".py", ".md", ".ps1"}


def project_version(root: Path = ROOT) -> str:
    with open(root / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def version_headers(root: Path = ROOT) -> dict[str, str]:
    """{relative path: version} for every file carrying a Version: header."""
    out = {}
    for p in sorted(root.rglob("*")):
        if p.suffix not in _SUFFIXES or not p.is_file():
            continue
        if _SKIP_DIRS & set(p.relative_to(root).parts):
            continue
        m = _HEADER_RE.search(p.read_bytes())
        if m:
            out[p.relative_to(root).as_posix()] = m.group(1).decode()
    return out


def changelog_heading(version: str, root: Path = ROOT) -> "str | None":
    """The '## vX.Y …' line for exactly this version, or None."""
    pat = re.compile(rf"^## v{re.escape(version)}(?: .*)?$", re.MULTILINE)
    m = pat.search((root / "CHANGELOG.md").read_text(encoding="utf-8"))
    return m.group(0) if m else None


def check(tag: "str | None" = None, root: Path = ROOT) -> list[str]:
    errors = []
    version = project_version(root)
    for path, v in version_headers(root).items():
        if v != version:
            errors.append(f"{path}: Version {v} != pyproject {version}")
    if tag is not None:
        tag_version = tag.removeprefix("refs/tags/").removeprefix("v")
        if tag_version != version:
            errors.append(f"tag {tag} != pyproject version {version} — bump "
                          "pyproject.toml and the Version: headers first")
        heading = changelog_heading(tag_version, root)
        if heading is None:
            errors.append(f"CHANGELOG.md has no '## v{tag_version}' section")
        elif "unreleased" in heading.lower():
            errors.append(f"CHANGELOG.md section is still '{heading}' — give it a date")
    return errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tag", help="release tag, e.g. v0.31 or refs/tags/v0.31")
    args = ap.parse_args(argv)
    errors = check(args.tag)
    for e in errors:
        print(f"::error::{e}" if args.tag else f"error: {e}", file=sys.stderr)
    if not errors:
        print(f"OK: version {project_version()}"
              + (f", tag {args.tag}" if args.tag else ""))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
