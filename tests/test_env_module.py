"""
$SEDO_MODULE (same as --module) and $SEDO_MODULE_DIRS (extra auto-discovery
directories, searched before the built-in list).
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from _console import module_from_env
from pkcs11_signer import PKCS11Signer, module_candidates
from virtual_signer import VirtualSigner


class TestModuleFromEnv:
    def test_argv_wins(self, monkeypatch):
        monkeypatch.setenv("SEDO_MODULE", "env.dll")
        assert module_from_env("argv.dll") == "argv.dll"

    def test_env_used_without_argv(self, monkeypatch):
        monkeypatch.setenv("SEDO_MODULE", "env.dll")
        assert module_from_env(None) == "env.dll"

    def test_empty_env_means_auto(self, monkeypatch):
        monkeypatch.setenv("SEDO_MODULE", "")
        assert module_from_env(None) is None


class TestModuleDirs:
    def test_dirs_are_searched_first(self, tmp_path, monkeypatch):
        d = tmp_path / "End User"
        d.mkdir()
        (d / "Av337CryptokiD.dll").write_bytes(b"x")
        monkeypatch.setenv("SEDO_MODULE_DIRS", str(d))
        found = PKCS11Signer._find_module()
        assert found == str(d / "Av337CryptokiD.dll")

    def test_several_dirs_in_order(self, tmp_path, monkeypatch):
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (b / "PKCS11.EKeyAlmaz1C.dll").write_bytes(b"x")
        monkeypatch.setenv("SEDO_MODULE_DIRS", os.pathsep.join([str(a), str(b)]))
        assert PKCS11Signer._find_module() == str(b / "PKCS11.EKeyAlmaz1C.dll")

    def test_known_names_only(self, tmp_path, monkeypatch):
        (tmp_path / "random.dll").write_bytes(b"x")
        monkeypatch.setenv("SEDO_MODULE_DIRS", str(tmp_path))
        cands = module_candidates(PKCS11Signer.DEFAULT_MODULE_PATHS)
        assert str(tmp_path / "random.dll") not in cands
        assert str(tmp_path / "Av337CryptokiD.dll") in cands

    def test_builtin_list_still_follows(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEDO_MODULE_DIRS", str(tmp_path))
        cands = module_candidates(PKCS11Signer.DEFAULT_MODULE_PATHS)
        assert cands[-len(PKCS11Signer.DEFAULT_MODULE_PATHS):] == \
            PKCS11Signer.DEFAULT_MODULE_PATHS

    def test_missing_dir_is_skipped_with_warning(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setenv("SEDO_MODULE_DIRS", str(tmp_path / "nope"))
        assert module_candidates(["C:\\x\\A.dll"]) == ["C:\\x\\A.dll"]
        assert "not a directory" in caplog.text

    def test_unset_changes_nothing(self, monkeypatch):
        monkeypatch.delenv("SEDO_MODULE_DIRS", raising=False)
        assert module_candidates(PKCS11Signer.DEFAULT_MODULE_PATHS) == \
            PKCS11Signer.DEFAULT_MODULE_PATHS

    def test_virtual_uses_the_same_dirs(self, tmp_path, monkeypatch):
        (tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll").write_bytes(b"x")
        monkeypatch.setenv("SEDO_MODULE_DIRS", str(tmp_path))
        assert VirtualSigner._find_module() == str(tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll")


class TestCLIs:
    def test_sedo_client_passes_env_module(self, tmp_path, monkeypatch):
        from sedo_client import main
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("SEDO_MODULE", r"C:\x\Av337CryptokiD.dll")
        monkeypatch.setattr(sys, "argv", ["sedo-client", "--pin", "1"])
        with patch("sedo_client.SEDOClient") as cls:
            main()
        assert cls.call_args.kwargs["module_path"] == r"C:\x\Av337CryptokiD.dll"

    def test_opensc_cli_accepts_env_module(self, monkeypatch):
        from opensc_signer import main
        monkeypatch.setenv("SEDO_MODULE", "m.dll")
        monkeypatch.setattr(sys, "argv", ["opensc_signer", "--list-slots"])
        fake = MagicMock()
        fake.list_slots.return_value = ""
        with patch("opensc_signer.OpenSCSigner", return_value=fake) as cls:
            main()
        assert cls.call_args.kwargs["module_path"] == "m.dll"

    def test_opensc_cli_without_module_is_a_usage_error(self, monkeypatch):
        from opensc_signer import main
        monkeypatch.delenv("SEDO_MODULE", raising=False)
        monkeypatch.setattr(sys, "argv", ["opensc_signer", "--list-slots"])
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 2
