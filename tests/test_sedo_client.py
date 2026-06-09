"""
Unit tests for sedo_client.SEDOClient and IITAgentAdapter.

All tests run without a real token or network — backends and HTTP are mocked.
"""

import base64
import os
import sys
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
    def test_exit_calls_logout(self):
        signer = FakeSigner()
        signer.logged_in = True
        with patch("sedo_client.SEDOClient._pick_backend", return_value=signer):
            with SEDOClient() as client:
                assert client.signer is signer
        assert not signer.logged_in

    def test_exit_closes_session_even_if_logout_raises(self):
        """HTTP session is closed even if signer.logout() throws."""
        signer = FakeSigner()
        signer.logout = MagicMock(side_effect=RuntimeError("boom"))
        with patch("sedo_client.SEDOClient._pick_backend", return_value=signer):
            client = SEDOClient()
        client.session = MagicMock()
        with pytest.raises(RuntimeError, match="boom"):
            client.__exit__(None, None, None)
        client.session.close.assert_called_once()


# ─── Backend mechanism selection (Avest vs IIT) ─────────────

class TestOpenSCMechanismSelection:
    def _capture_opensc(self, module_path):
        """Build a SEDOClient with opensc backend, capturing OpenSCSigner kwargs."""
        captured = {}

        def fake_signer(**kwargs):
            captured.update(kwargs)
            return FakeSigner()

        with patch("opensc_signer.OpenSCSigner", side_effect=fake_signer):
            SEDOClient(backend="opensc", module_path=module_path)
        return captured

    def test_iit_module_gets_vendor_mechanism(self):
        captured = self._capture_opensc(r"C:\libs\PKCS11.EKeyAlmaz1C.dll")
        assert captured["mechanism"] == "0x80420031"

    def test_avest_module_gets_standard_mechanism(self):
        captured = self._capture_opensc(r"C:\Avest\Av337CryptokiD.dll")
        assert captured["mechanism"] == "0x00000352"


# ─── HTTP auth flows ────────────────────────────────────────

def _make_client(url="https://sedo.mod.gov.ua"):
    signer = FakeSigner()
    with patch("sedo_client.SEDOClient._pick_backend", return_value=signer):
        client = SEDOClient(sedo_url=url)
    client.session = MagicMock()
    return client, signer


class TestFlowOIDC:
    def test_no_idp_redirect_returns_false(self):
        client, _ = _make_client()
        client.session.get.return_value = MagicMock(
            headers={"Location": "https://sedo.mod.gov.ua/home"})
        assert client._flow_oidc(b"cert", "1234") is False

    def test_idp_redirect_still_unimplemented(self):
        """id.gov.ua detected but OIDC dance not implemented → False."""
        client, _ = _make_client()
        client.session.get.return_value = MagicMock(
            headers={"Location": "https://id.gov.ua/auth?x=1"})
        assert client._flow_oidc(b"cert", "1234") is False


class TestFlowDirectKEP:
    def test_success(self):
        client, signer = _make_client()
        challenge = base64.b64encode(b"challenge-bytes").decode()
        init = MagicMock(status_code=200)
        init.json.return_value = {"challenge": challenge, "session_id": "s1"}
        verify = MagicMock(ok=True)
        client.session.post.side_effect = [init, verify]

        assert client._flow_direct_kep(b"cert", "1234") is True
        # signer.sign must have been called with the decoded challenge
        assert client.session.post.call_count == 2
        # verify URL ends with /verify
        verify_call = client.session.post.call_args_list[1]
        assert verify_call.args[0].endswith("/verify")

    def test_all_candidates_non_200_returns_false(self):
        client, _ = _make_client()
        client.session.post.return_value = MagicMock(status_code=404)
        assert client._flow_direct_kep(b"cert", "1234") is False

    def test_non_string_challenge_skipped(self):
        client, _ = _make_client()
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"challenge": {"nested": "dict"}}
        client.session.post.return_value = resp
        assert client._flow_direct_kep(b"cert", "1234") is False


class TestFlowCMSPost:
    def test_raises_not_implemented(self):
        client, _ = _make_client()
        with pytest.raises(NotImplementedError):
            client._flow_cms_post(b"cert", "1234")


class TestAuthorize:
    def test_all_flows_fail_raises(self):
        client, _ = _make_client()
        # oidc GET: no idp; direct_kep POST: all 404; cms_post raises
        client.session.get.return_value = MagicMock(headers={"Location": ""})
        client.session.post.return_value = MagicMock(status_code=404)
        with pytest.raises(RuntimeError, match="All auth flows failed"):
            client.authorize("1234")

    def test_success_returns_none(self):
        client, _ = _make_client()
        client.session.get.return_value = MagicMock(headers={"Location": ""})
        challenge = base64.b64encode(b"abc").decode()
        init = MagicMock(status_code=200)
        init.json.return_value = {"challenge": challenge}
        verify = MagicMock(ok=True)
        client.session.post.side_effect = [init, verify]
        assert client.authorize("1234") is None


class TestFetchInbox:
    def test_returns_documents(self):
        client, _ = _make_client()
        resp = MagicMock()
        resp.json.return_value = {"documents": [{"id": "d1"}, {"id": "d2"}]}
        resp.raise_for_status = MagicMock()
        client.session.get.return_value = resp
        docs = client.fetch_inbox()
        assert [d["id"] for d in docs] == ["d1", "d2"]

    def test_passes_since_param(self):
        client, _ = _make_client()
        resp = MagicMock()
        resp.json.return_value = {"documents": []}
        client.session.get.return_value = resp
        client.fetch_inbox(since="2026-06-01")
        kwargs = client.session.get.call_args.kwargs
        assert kwargs["params"] == {"since": "2026-06-01"}

    def test_raises_on_http_error(self):
        client, _ = _make_client()
        resp = MagicMock()
        resp.raise_for_status.side_effect = RuntimeError("HTTP 500")
        client.session.get.return_value = resp
        with pytest.raises(RuntimeError, match="HTTP 500"):
            client.fetch_inbox()


class TestDownloadDocument:
    def test_writes_zip_and_creates_dir(self, tmp_path):
        client, _ = _make_client()
        resp = MagicMock(content=b"PK\x03\x04zip")
        resp.raise_for_status = MagicMock()
        client.session.get.return_value = resp

        out_dir = tmp_path / "downloads" / "2026-06-08"
        assert not out_dir.exists()
        path = client.download_document("doc-42", out_dir)
        assert path == out_dir / "doc-42.zip"
        assert path.read_bytes() == b"PK\x03\x04zip"


# ─── Windows console encoding ───────────────────────────────

class TestForceUtf8IO:
    def test_emoji_print_survives_cp1251(self, monkeypatch):
        """force_utf8_io makes emoji printable on a cp1251 console."""
        import io
        from sedo_client import force_utf8_io

        fake_out = io.TextIOWrapper(io.BytesIO(), encoding="cp1251")
        fake_err = io.TextIOWrapper(io.BytesIO(), encoding="cp1251")
        monkeypatch.setattr("sys.stdout", fake_out)
        monkeypatch.setattr("sys.stderr", fake_err)

        force_utf8_io()
        # Would raise UnicodeEncodeError on raw cp1251 without the fix
        print("✓ Авторизація успішна 📄")
        sys.stdout.flush()

    def test_no_crash_on_non_reconfigurable_stream(self, monkeypatch):
        """Streams without reconfigure() are skipped silently."""
        from sedo_client import force_utf8_io

        class Dummy:
            pass

        monkeypatch.setattr("sys.stdout", Dummy())
        monkeypatch.setattr("sys.stderr", Dummy())
        force_utf8_io()  # must not raise
