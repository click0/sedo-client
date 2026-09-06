"""
Security regression tests (v0.29 audit S1, S3, S4, S5, S8).

All mocked — no token, no network, no PyKCS11 required.
"""

import logging
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import iit_client
from iit_client import IITClient, probe_port
from sedo_client import SEDOClient, _safe_doc_id, _build_parser
from opensc_signer import OpenSCSigner


# ─── S1: PIN must never reach the debug log ──────────────────

class TestPinNotLogged:
    @patch("iit_client.requests.Session")
    def test_read_private_key_params_redacted(self, mock_session_cls, caplog):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"jsonrpc": "2.0", "id": 1, "result": None},
        )
        client = IITClient(port=9100)
        with caplog.at_level(logging.DEBUG, logger="iit_client"):
            client.read_private_key({"devIndex": 0}, "9876")
        assert "9876" not in caplog.text
        assert "ReadPrivateKey" in caplog.text
        assert "[***]" in caplog.text

    @patch("iit_client.requests.Session")
    def test_non_secret_method_params_still_logged(self, mock_session_cls, caplog):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"jsonrpc": "2.0", "id": 1, "result": None},
        )
        client = IITClient(port=9100)
        with caplog.at_level(logging.DEBUG, logger="iit_client"):
            client.call("GetOwnCertificate", [7])
        assert "[7]" in caplog.text


# ─── S4: TLS verification skipped only on loopback ──────────

class TestTlsVerifyOnlyLoopback:
    def test_remote_https_keeps_verification(self):
        client = IITClient(host="10.0.0.5", port=8083, use_https=True)
        assert client.session.verify is True

    def test_loopback_https_skips_verification(self):
        client = IITClient(host="127.0.0.1", port=8083, use_https=True)
        assert client.session.verify is False

    def test_localhost_name_is_loopback(self):
        assert iit_client._is_loopback("localhost") is True
        assert iit_client._is_loopback("::1") is True
        assert iit_client._is_loopback("10.0.0.5") is False
        assert iit_client._is_loopback("not-an-ip") is False

    @patch("iit_client.requests.options")
    def test_probe_port_verify_kwarg(self, mock_options):
        mock_options.return_value = MagicMock(status_code=200)
        probe_port("10.0.0.5", 8083, use_https=True)
        assert mock_options.call_args.kwargs["verify"] is True
        probe_port("127.0.0.1", 8083, use_https=True)
        assert mock_options.call_args.kwargs["verify"] is False


# ─── S3: server-supplied doc_id is sanitized ────────────────

class FakeSigner:
    def login(self, pin): pass
    def get_certificate(self): return b"\x30\x82"
    def sign(self, data): return b"\x00" * 64
    def logout(self): pass


def _make_client():
    with patch("sedo_client.SEDOClient._pick_backend", return_value=FakeSigner()):
        client = SEDOClient()
    client.session = MagicMock()
    return client


class TestSafeDocId:
    @pytest.mark.parametrize("bad", ["../../x", "a/b", "a\\b", "", "C:evil", "..", 123, None])
    def test_rejects_unsafe(self, bad):
        with pytest.raises(ValueError):
            _safe_doc_id(bad)

    @pytest.mark.parametrize("good", ["doc-42", "ABC_123.zip", "a.b-c_d"])
    def test_accepts_safe(self, good):
        assert _safe_doc_id(good) == good

    def test_download_refuses_traversal_without_request(self, tmp_path):
        client = _make_client()
        with pytest.raises(ValueError):
            client.download_document("../../etc/passwd", tmp_path)
        client.session.get.assert_not_called()

    def test_download_result_stays_inside_output_dir(self, tmp_path):
        client = _make_client()
        resp = MagicMock(content=b"PK")
        resp.raise_for_status = MagicMock()
        client.session.get.return_value = resp
        out = client.download_document("doc-42", tmp_path)
        assert out.resolve().is_relative_to(tmp_path.resolve())
        # URL segment is quoted and the id is used verbatim in the path
        url = client.session.get.call_args.args[0]
        assert url.endswith("/api/documents/doc-42/export")


# ─── S5: PIN from SEDO_PIN env, real parser choices ─────────

class TestPinFromEnvironment:
    def test_env_pin_used_without_prompt(self, monkeypatch):
        monkeypatch.setenv("SEDO_PIN", "env-pin")
        monkeypatch.setattr(sys, "argv", ["sedo-client"])
        fake_ctx = MagicMock()
        with patch("sedo_client.SEDOClient", return_value=fake_ctx) as cls, \
             patch("getpass.getpass") as gp:
            from sedo_client import main
            main()
            gp.assert_not_called()
        sedo = fake_ctx.__enter__.return_value
        sedo.authorize.assert_called_once_with("env-pin")

    def test_argv_pin_takes_precedence_over_env(self, monkeypatch):
        monkeypatch.setenv("SEDO_PIN", "env-pin")
        monkeypatch.setattr(sys, "argv", ["sedo-client", "--pin", "argv-pin"])
        fake_ctx = MagicMock()
        with patch("sedo_client.SEDOClient", return_value=fake_ctx):
            from sedo_client import main
            main()
        fake_ctx.__enter__.return_value.authorize.assert_called_once_with("argv-pin")

    def test_build_parser_real_choices(self):
        parser = _build_parser()
        assert parser.parse_args(["--backend", "virtual"]).backend == "virtual"
        with pytest.raises(SystemExit):
            parser.parse_args(["--backend", "bogus"])


# ─── S8: opensc temp files live in a private dir and are removed ──

class TestOpenSCTempDir:
    def _signer(self, tmp_path):
        tool = tmp_path / "pkcs11-tool"
        tool.write_bytes(b"fake")
        module = tmp_path / "PKCS11.dll"
        module.write_bytes(b"fake")
        s = OpenSCSigner(module_path=str(module), pkcs11_tool=str(tool))
        s.login("1234")
        return s

    @patch("opensc_signer.subprocess.run")
    def test_sign_uses_private_tmpdir_and_cleans_up(self, mock_run, tmp_path):
        signer = self._signer(tmp_path)
        seen = {}

        def fake_run(cmd, **kwargs):
            args = list(cmd)
            inp = Path(args[args.index("--input-file") + 1])
            out = Path(args[args.index("--output-file") + 1])
            seen["inp"], seen["out"] = inp, out
            seen["mode"] = stat.S_IMODE(inp.parent.stat().st_mode)
            out.write_bytes(b"\x00" * 64)
            return subprocess.CompletedProcess(args=cmd, returncode=0,
                                               stdout=b"", stderr=b"")

        mock_run.side_effect = fake_run
        assert signer.sign(b"payload") == b"\x00" * 64
        assert seen["inp"].parent == seen["out"].parent
        assert seen["inp"].parent.name.startswith("sedo-sign-")
        if os.name != "nt":
            assert seen["mode"] == 0o700
        assert not seen["inp"].parent.exists()

    @patch("opensc_signer.subprocess.run")
    def test_get_certificate_cleans_up(self, mock_run, tmp_path):
        signer = self._signer(tmp_path)
        seen = {}

        def fake_run(cmd, **kwargs):
            args = list(cmd)
            out = Path(args[args.index("--output-file") + 1])
            seen["out"] = out
            out.write_bytes(b"\x30\x82")
            return subprocess.CompletedProcess(args=cmd, returncode=0,
                                               stdout=b"", stderr=b"")

        mock_run.side_effect = fake_run
        assert signer.get_certificate() == b"\x30\x82"
        assert seen["out"].parent.name.startswith("sedo-cert-")
        assert not seen["out"].parent.exists()
