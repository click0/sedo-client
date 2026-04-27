"""
Unit tests for opensc_signer.OpenSCSigner.

Tests mock subprocess calls — no real pkcs11-tool or token needed.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from opensc_signer import OpenSCSigner, OpenSCNotFound


class TestFindTool:
    def test_find_tool_in_path(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/pkcs11-tool"
                            if "pkcs11" in name else None)
        assert OpenSCSigner._find_tool() == "/usr/bin/pkcs11-tool"

    def test_find_tool_standard_paths(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        tool = tmp_path / "pkcs11-tool"
        tool.write_bytes(b"fake")
        monkeypatch.setattr(OpenSCSigner, "DEFAULT_PKCS11_TOOL_PATHS",
                            [str(tool)])
        assert OpenSCSigner._find_tool() == str(tool)

    def test_find_tool_raises(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        monkeypatch.setattr(OpenSCSigner, "DEFAULT_PKCS11_TOOL_PATHS", [])
        with pytest.raises(OpenSCNotFound):
            OpenSCSigner._find_tool()


class TestOpenSCSignerInit:
    def test_raises_if_tool_missing(self, tmp_path):
        module = tmp_path / "PKCS11.dll"
        module.write_bytes(b"fake")
        with pytest.raises(OpenSCNotFound):
            OpenSCSigner(module_path=str(module),
                         pkcs11_tool="/nonexistent/pkcs11-tool")

    def test_raises_if_module_missing(self, tmp_path):
        tool = tmp_path / "pkcs11-tool"
        tool.write_bytes(b"fake")
        with pytest.raises(FileNotFoundError, match="PKCS#11 module"):
            OpenSCSigner(module_path="/nonexistent/module.dll",
                         pkcs11_tool=str(tool))

    def test_init_ok(self, tmp_path):
        tool = tmp_path / "pkcs11-tool"
        tool.write_bytes(b"fake")
        module = tmp_path / "PKCS11.dll"
        module.write_bytes(b"fake")
        signer = OpenSCSigner(module_path=str(module),
                              pkcs11_tool=str(tool))
        assert signer._tool == str(tool)
        assert signer._module == str(module)


class TestLoginLogout:
    def _make_signer(self, tmp_path):
        tool = tmp_path / "pkcs11-tool"
        tool.write_bytes(b"fake")
        module = tmp_path / "PKCS11.dll"
        module.write_bytes(b"fake")
        return OpenSCSigner(module_path=str(module),
                            pkcs11_tool=str(tool))

    def test_login_stores_pin(self, tmp_path):
        signer = self._make_signer(tmp_path)
        signer.login("1234")
        assert signer._pin == "1234"

    def test_logout_clears_pin(self, tmp_path):
        signer = self._make_signer(tmp_path)
        signer.login("1234")
        signer.logout()
        assert signer._pin is None

    def test_operations_without_login_raise(self, tmp_path):
        signer = self._make_signer(tmp_path)
        with pytest.raises(RuntimeError, match="PIN"):
            signer.list_objects()
        with pytest.raises(RuntimeError, match="PIN"):
            signer.get_certificate()
        with pytest.raises(RuntimeError, match="PIN"):
            signer.sign(b"data")


class TestRun:
    def _make_signer(self, tmp_path):
        tool = tmp_path / "pkcs11-tool"
        tool.write_bytes(b"fake")
        module = tmp_path / "PKCS11.dll"
        module.write_bytes(b"fake")
        return OpenSCSigner(module_path=str(module),
                            pkcs11_tool=str(tool))

    @patch("opensc_signer.subprocess.run")
    def test_run_passes_module(self, mock_run, tmp_path):
        signer = self._make_signer(tmp_path)
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"output", stderr=b""
        )
        result = signer._run(["--list-slots"])
        cmd = mock_run.call_args[0][0]
        assert "--module" in cmd
        assert str(tmp_path / "PKCS11.dll") in cmd
        assert "--list-slots" in cmd

    @patch("opensc_signer.subprocess.run")
    def test_list_mechanisms(self, mock_run, tmp_path):
        signer = self._make_signer(tmp_path)
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=b"  0x80420031 line1\n  0x80420032 line2\n", stderr=b""
        )
        mechs = signer.list_mechanisms()
        assert len(mechs) == 2
        assert "0x80420031" in mechs[0]

    @patch("opensc_signer.subprocess.run")
    def test_sign_creates_temp_files(self, mock_run, tmp_path):
        signer = self._make_signer(tmp_path)
        signer.login("1234")

        def fake_run(cmd, **kwargs):
            # Write fake signature to output file
            for i, arg in enumerate(cmd):
                if arg == "--output-file" and i + 1 < len(cmd):
                    Path(cmd[i + 1]).write_bytes(b"\x00" * 64)
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=b"", stderr=b""
            )

        mock_run.side_effect = fake_run
        sig = signer.sign(b"test data")
        assert len(sig) == 64

    @patch("opensc_signer.subprocess.run")
    def test_sign_raises_on_failure(self, mock_run, tmp_path):
        signer = self._make_signer(tmp_path)
        signer.login("1234")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=b"", stderr=b"CKR_PIN_INCORRECT"
        )
        with pytest.raises(RuntimeError, match="sign failed"):
            signer.sign(b"test data")

    @patch("opensc_signer.subprocess.run")
    def test_get_certificate_reads_output(self, mock_run, tmp_path):
        signer = self._make_signer(tmp_path)
        signer.login("1234")
        fake_cert = b"\x30\x82\x02\x00" + b"\x00" * 50

        def fake_run(cmd, **kwargs):
            for i, arg in enumerate(cmd):
                if arg == "--output-file" and i + 1 < len(cmd):
                    Path(cmd[i + 1]).write_bytes(fake_cert)
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=b"", stderr=b""
            )

        mock_run.side_effect = fake_run
        cert = signer.get_certificate()
        assert cert == fake_cert
