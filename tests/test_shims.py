"""The top-level modules of earlier versions, kept as shims of the sedo package."""

import importlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

SHIMS = {
    "_console": "sedo._console",
    "sedo_config": "sedo.config",
    "sedo_check": "sedo.check",
    "sedo_client": "sedo.client",
    "iit_client": "sedo.iit_client",
    "opensc_signer": "sedo.opensc_signer",
    "pkcs11_signer": "sedo.pkcs11_signer",
    "virtual_signer": "sedo.virtual_signer",
    "mechanism_ids": "sedo.mechanism_ids",
}

# The modules that were run as programs: `python sedo_client.py ...`.
SCRIPTS = ["sedo_client", "iit_client", "opensc_signer", "pkcs11_signer"]


@pytest.mark.parametrize("old, new", sorted(SHIMS.items()))
def test_import_warns_and_returns_the_package_module(old, new, monkeypatch):
    monkeypatch.delitem(sys.modules, old, raising=False)
    with pytest.warns(DeprecationWarning, match=f"use '{new}'"):
        mod = importlib.import_module(old)
    assert mod is importlib.import_module(new)


def test_a_patch_through_the_old_name_reaches_the_real_module(monkeypatch):
    monkeypatch.delitem(sys.modules, "iit_client", raising=False)
    with pytest.warns(DeprecationWarning):
        import iit_client
    from sedo import iit_client as real
    monkeypatch.setattr(iit_client, "AGENT_CA_ENV", "SEDO_TEST_SHIM")
    assert real.AGENT_CA_ENV == "SEDO_TEST_SHIM"


@pytest.mark.parametrize("script", SCRIPTS)
def test_script_runs_the_program_without_a_warning(script):
    # -W error: a DeprecationWarning on the way to main() would fail the run.
    r = subprocess.run([sys.executable, "-W", "error::DeprecationWarning",
                        str(ROOT / f"{script}.py"), "--help"],
                       capture_output=True, text=True, encoding="utf-8",
                       cwd=ROOT, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("usage:")
    assert "Deprecat" not in r.stderr
