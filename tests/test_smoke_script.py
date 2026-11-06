"""
scripts/smoke_test.py: a check that does not apply on this OS is a skip, not a
failure, so the script exits 0 on a Linux controller or in CI without a DLL.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def smoke(monkeypatch):
    monkeypatch.delenv("SEDO_MODULE", raising=False)
    monkeypatch.delenv("SEDO_MODULE_DIRS", raising=False)
    spec = importlib.util.spec_from_file_location("smoke_test_script", ROOT / "scripts" / "smoke_test.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _missing():
    return patch("sedo.pkcs11_signer.PKCS11Signer._find_module",
                 side_effect=FileNotFoundError("PKCS#11 module not found"))


class TestModuleCheck:
    def test_no_dll_outside_windows_is_a_skip(self, smoke, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        with _missing(), pytest.raises(smoke.Skip, match="SEDO_MODULE unset"):
            smoke.t_dll()

    def test_no_dll_on_windows_fails(self, smoke, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        with _missing(), pytest.raises(AssertionError, match="not found"):
            smoke.t_dll()

    def test_found_by_search(self, smoke, tmp_path):
        dll = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        dll.write_bytes(b"MZ" + b"\0" * 10)
        with patch("sedo.pkcs11_signer.PKCS11Signer._find_module", return_value=str(dll)):
            assert smoke.t_dll() == f"{dll} (12 bytes)"

    @pytest.mark.parametrize("platform", ["linux", "win32"])
    def test_explicit_module_is_checked_everywhere(self, smoke, tmp_path, monkeypatch, platform):
        monkeypatch.setattr(sys, "platform", platform)
        so = tmp_path / "libsofthsm2.so"
        so.write_bytes(b"\x7fELF")
        monkeypatch.setenv("SEDO_MODULE", str(so))
        with _missing() as search:
            assert smoke.t_dll() == f"{so} (4 bytes)"
        search.assert_not_called()
        monkeypatch.setenv("SEDO_MODULE", str(tmp_path / "gone.dll"))
        with pytest.raises(AssertionError, match=r"\$SEDO_MODULE does not exist"):
            smoke.t_dll()

    def test_label_names_the_real_file(self, smoke):
        names = [name for name, _ in smoke.TESTS]
        assert any("PKCS11.EKeyAlmaz1C.dll" in n and "Av337CryptokiD.dll" in n for n in names)
        assert not any("PKCS11_EKeyAlmaz1C" in n for n in names)


class TestMain:
    def test_linux_without_dll_exits_zero(self, smoke, monkeypatch, capsys, fake_pykcs11):
        monkeypatch.setattr(sys, "platform", "linux")
        with _missing():
            assert smoke.main() == 0
        out = capsys.readouterr().out
        assert out.count("– ") == 3                     # SCardSvr, module, registry
        assert out.rstrip().endswith(f"{len(smoke.TESTS) - 3} passed, 3 skipped, 0 failed")

    def test_a_failure_still_exits_one(self, smoke, monkeypatch, capsys, fake_pykcs11):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("SEDO_MODULE", "/nonexistent/module.so")
        assert smoke.main() == 1
        assert "✗ PKCS#11 module" in capsys.readouterr().out
