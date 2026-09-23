"""
scripts/check_version.py — the version gate release.yml runs on a tag, and the
header-consistency check tests.yml runs on every push.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("check_version",
                                                  ROOT / "scripts" / "check_version.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cv = _load()


def _repo(tmp_path, version="0.31", heading="## v0.31 — 2026-10-01", headers=None):
    (tmp_path / "pyproject.toml").write_text(f'[project]\nname = "x"\nversion = "{version}"\n')
    (tmp_path / "CHANGELOG.md").write_text(f"# CHANGELOG\n\n{heading}\n\n- x\n\n## v0.30 — 2026-09-12\n")
    for name, content in (headers or {}).items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    return tmp_path


def test_repository_is_consistent():
    assert cv.check(root=ROOT) == []


def test_every_python_module_carries_a_header():
    headers = cv.version_headers(ROOT)
    for mod in ("sedo_client.py", "iit_client.py", "opensc_signer.py", "pkcs11_signer.py",
                "virtual_signer.py", "mechanism_ids.py", "_console.py",
                "opensc-test-almaz.ps1"):
        assert mod in headers, mod


def test_drifted_header_is_reported(tmp_path):
    root = _repo(tmp_path, headers={
        "a.py": b'"""\nVersion:  0.31\n"""\n',
        "b.ps1": "# Version:  0.27\n# Опис\n".encode("cp1251"),   # CP1251 like the real one
    })
    errors = cv.check(root=root)
    assert errors == ["b.ps1: Version 0.27 != pyproject 0.31"]


@pytest.mark.parametrize("tag", ["v0.31", "refs/tags/v0.31"])
def test_release_gate_passes(tmp_path, tag):
    assert cv.check(tag=tag, root=_repo(tmp_path)) == []


def test_tag_ahead_of_pyproject(tmp_path):
    """The case the gate exists for: tag v0.31 while pyproject says 0.30."""
    root = _repo(tmp_path, version="0.30", heading="## v0.31 — 2026-10-01")
    errors = cv.check(tag="v0.31", root=root)
    assert any("!= pyproject version 0.30" in e for e in errors)


def test_unreleased_section_blocks_the_tag(tmp_path):
    root = _repo(tmp_path, heading="## v0.31 — unreleased")
    assert any("unreleased" in e for e in cv.check(tag="v0.31", root=root))


def test_missing_section_blocks_the_tag(tmp_path):
    root = _repo(tmp_path, version="0.32", heading="## v0.31 — 2026-10-01")
    assert any("no '## v0.32' section" in e for e in cv.check(tag="v0.32", root=root))


def test_heading_match_is_exact(tmp_path):
    """v0.3 must not match the v0.30 / v0.31 headings."""
    root = _repo(tmp_path)
    assert cv.changelog_heading("0.3", root) is None
    assert cv.changelog_heading("0.30", root) == "## v0.30 — 2026-09-12"


def test_cli_exit_codes(tmp_path, monkeypatch, capsys):
    assert cv.main([]) == 0
    assert cv.main(["--tag", "v99.0"]) == 1
    assert "::error::" in capsys.readouterr().err
