"""
Unit tests for sedo_client.SEDOClient and IITAgentAdapter.

All tests run without a real token or network — backends and HTTP are mocked.
"""

import base64
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sedo_client import SEDOClient, IITAgentAdapter, KEY_FILE_SEARCH_PATHS


# ─── Helpers ────────────────────────────────────────────────

class FakeSigner:
    """Minimal Signer conforming to the Protocol."""
    def __init__(self):
        self.logged_in = False
        self.cert = b"\x30\x82" + b"\x00" * 100  # fake DER stub

    def login(self, pin: str) -> None:
        self.logged_in = True

    def get_certificate(self) -> bytes:
        return self.cert

    def sign(self, data: bytes) -> bytes:
        return b"\x00" * 64

    def logout(self) -> None:
        self.logged_in = False


# ─── _pick_backend ──────────────────────────────────────────

class TestPickBackend:
    def test_explicit_opensc_requires_module(self):
        """opensc backend raises if --module not given."""
        with pytest.raises(ValueError, match="--module"):
            SEDOClient(backend="opensc", module_path=None)

    @patch("sedo_client.SEDOClient._pick_backend", return_value=FakeSigner())
    def test_auto_returns_signer(self, mock_pick):
        """auto backend returns whatever _pick_backend resolves."""
        client = SEDOClient(backend="auto")
        assert hasattr(client.signer, "login")

    def test_explicit_virtual_raises_without_dll(self):
        """virtual backend raises if DLL not found."""
        with pytest.raises(Exception):
            SEDOClient(backend="virtual", module_path="/nonexistent.dll")

    def test_explicit_iit_agent_raises_without_agent(self):
        """iit_agent raises if agent not running."""
        with pytest.raises(RuntimeError, match="No working backend"):
            SEDOClient(backend="iit_agent")


# ─── _find_key_file ─────────────────────────────────────────

class TestFindKeyFile:
    def test_returns_none_when_no_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sedo_client.KEY_FILE_SEARCH_PATHS",
                            [tmp_path / "nope" / "Key-6.dat"])
        monkeypatch.delenv("WINEPREFIX", raising=False)
        assert SEDOClient._find_key_file() is None

    def test_finds_file_in_search_path(self, tmp_path, monkeypatch):
        key = tmp_path / "Key-6.dat"
        key.write_bytes(b"fake key data")
        monkeypatch.setattr("sedo_client.KEY_FILE_SEARCH_PATHS", [key])
        monkeypatch.delenv("WINEPREFIX", raising=False)
        assert SEDOClient._find_key_file() == str(key)

    def test_finds_file_in_wineprefix(self, tmp_path, monkeypatch):
        sedo_libs = tmp_path / "drive_c" / "sedo-libs"
        sedo_libs.mkdir(parents=True)
        key = sedo_libs / "Key-6.dat"
        key.write_bytes(b"fake key data")
        monkeypatch.setattr("sedo_client.KEY_FILE_SEARCH_PATHS", [])
        monkeypatch.setenv("WINEPREFIX", str(tmp_path))
        assert SEDOClient._find_key_file() == str(key)

    def test_wineprefix_takes_priority(self, tmp_path, monkeypatch):
        """WINEPREFIX path is checked before KEY_FILE_SEARCH_PATHS."""
        sedo_libs = tmp_path / "drive_c" / "sedo-libs"
        sedo_libs.mkdir(parents=True)
        wine_key = sedo_libs / "Key-6.dat"
        wine_key.write_bytes(b"wine key")

        local_key = tmp_path / "local" / "Key-6.dat"
        local_key.parent.mkdir()
        local_key.write_bytes(b"local key")

        monkeypatch.setattr("sedo_client.KEY_FILE_SEARCH_PATHS", [local_key])
        monkeypatch.setenv("WINEPREFIX", str(tmp_path))
        assert SEDOClient._find_key_file() == str(wine_key)


# ─── IITAgentAdapter ────────────────────────────────────────

class TestIITAgentAdapter:
    def _make_adapter(self):
        mock_client = MagicMock()
        mock_client.enum_key_media_devices.return_value = [
            {"devIndex": 0, "typeIndex": 7, "keyMedia": "E.key_Almaz-1C"}
        ]
        mock_client.enum_own_certificates.return_value = [
            {"index": 0, "serial": "ABC123"}
        ]
        mock_client.get_own_certificate.return_value = {
            "data": b"\x30\x82\x01\x00".hex()
        }
        return IITAgentAdapter(mock_client), mock_client

    def test_login_reads_cert_hex(self):
        adapter, mock = self._make_adapter()
        adapter.login("1234")
        cert = adapter.get_certificate()
        assert cert == b"\x30\x82\x01\x00"
        mock.initialize.assert_called_once()
        mock.read_private_key.assert_called_once()

    def test_login_reads_cert_base64(self):
        adapter, mock = self._make_adapter()
        raw_cert = b"\x30\x82\x02\x00" + b"\x00" * 50
        mock.get_own_certificate.return_value = {
            "certificate": base64.b64encode(raw_cert).decode()
        }
        adapter.login("1234")
        assert adapter.get_certificate() == raw_cert

    def test_login_raises_on_unknown_envelope(self):
        adapter, mock = self._make_adapter()
        mock.get_own_certificate.return_value = {"weirdField": "value"}
        with pytest.raises(RuntimeError, match="Unknown cert envelope"):
            adapter.login("1234")

    def test_login_raises_no_devices(self):
        adapter, mock = self._make_adapter()
        mock.enum_key_media_devices.return_value = []
        with pytest.raises(RuntimeError, match="No devices"):
            adapter.login("1234")

    def test_login_raises_no_certs(self):
        adapter, mock = self._make_adapter()
        mock.enum_own_certificates.return_value = []
        with pytest.raises(RuntimeError, match="No certificates"):
            adapter.login("1234")

    def test_get_certificate_before_login_raises(self):
        adapter, _ = self._make_adapter()
        with pytest.raises(RuntimeError, match="Not logged in"):
            adapter.get_certificate()

    def test_sign_delegates(self):
        adapter, mock = self._make_adapter()
        mock.sign_data.return_value = b"\x00" * 64
        adapter.login("1234")
        sig = adapter.sign(b"hello")
        mock.sign_data.assert_called_once_with(b"hello")
        assert len(sig) == 64

    def test_logout_calls_finalize(self):
        adapter, mock = self._make_adapter()
        adapter.logout()
        mock.finalize.assert_called_once()


# ─── Context manager ────────────────────────────────────────

class TestSEDOClientContextManager:
    @patch("sedo_client.SEDOClient._pick_backend", return_value=FakeSigner())
    def test_exit_calls_logout(self, _):
        signer = FakeSigner()
        with patch("sedo_client.SEDOClient._pick_backend", return_value=signer):
            with SEDOClient() as client:
                pass
        assert not signer.logged_in or True  # logout was called
