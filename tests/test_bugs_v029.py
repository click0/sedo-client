"""
Regression tests for the v0.29 code-bug fixes (B1–B9).

All mocked — no token, no network, no real PyKCS11 (see ``fake_pykcs11``
fixture in conftest.py).
"""

import base64
import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

import iit_client
from iit_client import IITClient, IITAgentNotFound, probe_port
from mechanism_ids import choose_sign_mechanism
from opensc_signer import OpenSCSigner
from sedo_client import SEDOClient, IITAgentAdapter


# ─── shared helpers ──────────────────────────────────────────

class FakeSigner:
    def __init__(self):
        self.signed = []

    def login(self, pin): pass
    def get_certificate(self): return b"\x30\x82"

    def sign(self, data):
        self.signed.append(data)
        return b"\x00" * 64

    def logout(self): pass


def _make_client():
    signer = FakeSigner()
    with patch("sedo_client.SEDOClient._pick_backend", return_value=signer):
        client = SEDOClient()
    client.session = MagicMock()
    return client, signer


def _init_response(challenge, session_id="s1"):
    r = MagicMock(status_code=200)
    r.json.return_value = {"challenge": challenge, "session_id": session_id}
    return r


def _opensc(tmp_path, **kwargs):
    tool = tmp_path / "pkcs11-tool"
    tool.write_bytes(b"fake")
    module = tmp_path / "PKCS11.dll"
    module.write_bytes(b"fake")
    s = OpenSCSigner(module_path=str(module), pkcs11_tool=str(tool), **kwargs)
    s.login("1234")
    return s


# ─── B1: --key-file only validates; warn if not next to the DLL ──

class TestVirtualKeyFileWarning:
    def _module(self, tmp_path):
        mod = tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll"
        mod.write_bytes(b"fake")
        return mod

    def test_key_in_other_dir_warns(self, fake_pykcs11, tmp_path, caplog):
        from virtual_signer import VirtualSigner
        mod = self._module(tmp_path)
        other = tmp_path / "elsewhere"
        other.mkdir()
        key = other / "Key-6.dat"
        key.write_bytes(b"key")
        with caplog.at_level(logging.WARNING, logger="virtual_signer"):
            VirtualSigner(module_path=str(mod), key_file=str(key))
        assert "not next to the virtual module" in caplog.text

    def test_key_next_to_module_is_silent(self, fake_pykcs11, tmp_path, caplog):
        from virtual_signer import VirtualSigner
        mod = self._module(tmp_path)
        key = tmp_path / "Key-6.dat"
        key.write_bytes(b"key")
        with caplog.at_level(logging.WARNING, logger="virtual_signer"):
            VirtualSigner(module_path=str(mod), key_file=str(key))
        assert "not next to the virtual module" not in caplog.text

    def test_missing_key_file_still_raises(self, fake_pykcs11, tmp_path):
        from virtual_signer import VirtualSigner
        mod = self._module(tmp_path)
        with pytest.raises(FileNotFoundError, match="Key file"):
            VirtualSigner(module_path=str(mod),
                          key_file=str(tmp_path / "nope.dat"))


# ─── B2: keep probing candidates after a failed /verify ─────

class TestDirectKepKeepsProbing:
    def test_second_candidate_succeeds_after_first_verify_fails(self):
        client, _ = _make_client()
        challenge = base64.b64encode(b"abc").decode()
        client.session.post.side_effect = [
            _init_response(challenge), MagicMock(ok=False, status_code=401),
            _init_response(challenge), MagicMock(ok=True),
        ]
        assert client._flow_direct_kep(b"cert", "1234") is True
        assert client.session.post.call_count == 4

    def test_all_verifies_fail_returns_false(self):
        client, _ = _make_client()
        challenge = base64.b64encode(b"abc").decode()
        client.session.post.side_effect = [
            _init_response(challenge), MagicMock(ok=False, status_code=401),
        ] * 3
        assert client._flow_direct_kep(b"cert", "1234") is False
        assert client.session.post.call_count == 6


# ─── B3: teardown never raises on a lost agent ──────────────

class TestFinalizeSwallowsTransportErrors:
    @patch("iit_client.requests.Session")
    def test_finalize_with_connection_error(self, mock_session_cls):
        sess = MagicMock()
        mock_session_cls.return_value = sess
        sess.post.side_effect = requests.exceptions.ConnectionError("gone")
        client = IITClient()
        client._initialized = True
        client._session_id = "sid"
        client.finalize()  # must not raise
        assert client._initialized is False
        assert client._session_id is None
        assert sess.post.call_count == 2  # ResetPrivateKey + Finalize attempted

    def test_adapter_logout_swallows_agent_not_found(self, caplog):
        mock = MagicMock()
        mock.finalize.side_effect = IITAgentNotFound("agent died")
        adapter = IITAgentAdapter(mock)
        with caplog.at_level(logging.WARNING, logger="sedo_client"):
            adapter.logout()  # must not raise
        assert "finalize failed" in caplog.text

    def test_adapter_logout_propagates_unrelated_errors(self):
        mock = MagicMock()
        mock.finalize.side_effect = KeyError("bug")
        with pytest.raises(KeyError):
            IITAgentAdapter(mock).logout()


# ─── B4: GetOwnCertificate envelope guard ───────────────────

class TestCertEnvelope:
    def _adapter(self, cert_info):
        mock = MagicMock()
        mock.enum_key_media_devices.return_value = [{"devIndex": 0}]
        mock.enum_own_certificates.return_value = [{"index": 0}]
        mock.get_own_certificate.return_value = cert_info
        return IITAgentAdapter(mock)

    @pytest.mark.parametrize("bad", [None, "3082", 42, ["3082"]])
    def test_non_dict_raises_runtime_error(self, bad):
        with pytest.raises(RuntimeError, match="Unexpected GetOwnCertificate"):
            self._adapter(bad).login("1234")

    def test_data_base64_decoded(self):
        raw = b"\x30\x82\x01\x00" + b"\xab" * 8
        # Pick bytes whose base64 is not valid hex ("MIIB..." has non-hex chars)
        adapter = self._adapter({"data": base64.b64encode(raw).decode()})
        adapter.login("1234")
        assert adapter.get_certificate() == raw

    def test_data_hex_decoded(self):
        adapter = self._adapter({"data": "30820100"})
        adapter.login("1234")
        assert adapter.get_certificate() == b"\x30\x82\x01\x00"

    def test_garbage_raises_runtime_error_not_binascii(self):
        with pytest.raises(RuntimeError, match="neither hex nor base64"):
            self._adapter({"data": "zz!!"}).login("1234")

    def test_non_string_field_raises(self):
        with pytest.raises(RuntimeError, match="not a string"):
            self._adapter({"data": 12345}).login("1234")

    def test_sign_before_login_raises(self):
        with pytest.raises(RuntimeError, match="Not logged in"):
            self._adapter({"data": "3082"}).sign(b"x")


# ─── B5: empty pkcs11-tool output is an error; cert_id is configurable ──

class TestOpenSCEmptyOutput:
    @staticmethod
    def _empty_run(cmd, **kwargs):
        args = list(cmd)
        Path(args[args.index("--output-file") + 1]).write_bytes(b"")
        return subprocess.CompletedProcess(args=cmd, returncode=0,
                                           stdout=b"", stderr=b"")

    @patch("opensc_signer.subprocess.run")
    def test_sign_empty_output_raises(self, mock_run, tmp_path):
        mock_run.side_effect = self._empty_run
        with pytest.raises(RuntimeError, match="empty signature"):
            _opensc(tmp_path).sign(b"data")

    @patch("opensc_signer.subprocess.run")
    def test_get_certificate_empty_output_raises(self, mock_run, tmp_path):
        mock_run.side_effect = self._empty_run
        with pytest.raises(RuntimeError, match="empty certificate"):
            _opensc(tmp_path).get_certificate()

    @patch("opensc_signer.subprocess.run")
    def test_cert_id_kwarg_used(self, mock_run, tmp_path):
        seen = {}

        def fake_run(cmd, **kwargs):
            args = list(cmd)
            seen["id"] = args[args.index("--id") + 1]
            Path(args[args.index("--output-file") + 1]).write_bytes(b"\x30")
            return subprocess.CompletedProcess(args=cmd, returncode=0,
                                               stdout=b"", stderr=b"")

        mock_run.side_effect = fake_run
        assert _opensc(tmp_path, cert_id="02").get_certificate() == b"\x30"
        assert seen["id"] == "02"
        # explicit override still wins
        _opensc(tmp_path).get_certificate(object_id="07")
        assert seen["id"] == "07"


# ─── B6: opensc CLI prompts for PIN instead of silently doing nothing ──

class TestOpenSCMainPrompts:
    def test_get_cert_without_pin_prompts(self, tmp_path, monkeypatch):
        from opensc_signer import main
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv",
                            ["opensc_signer", "--module", "m.dll", "--get-cert"])
        fake = MagicMock()
        fake.get_certificate.return_value = b"\x30\x82"
        with patch("opensc_signer.OpenSCSigner", return_value=fake), \
             patch("getpass.getpass", return_value="9999") as gp:
            main()
        gp.assert_called_once()
        fake.login.assert_called_once_with("9999")
        fake.get_certificate.assert_called_once()
        assert (tmp_path / "almaz-cert.der").read_bytes() == b"\x30\x82"

    def test_list_slots_only_does_not_prompt(self, tmp_path, monkeypatch):
        from opensc_signer import main
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv",
                            ["opensc_signer", "--module", "m.dll", "--list-slots"])
        fake = MagicMock()
        fake.list_slots.return_value = "slot 0"
        with patch("opensc_signer.OpenSCSigner", return_value=fake), \
             patch("getpass.getpass") as gp:
            main()
        gp.assert_not_called()
        fake.login.assert_not_called()


# ─── B7: non-base64 challenge is signed verbatim ────────────

class TestChallengeDecoding:
    def test_plaintext_nonce_signed_raw(self):
        client, signer = _make_client()
        nonce = "nonce!not/b64"
        client.session.post.side_effect = [_init_response(nonce), MagicMock(ok=True)]
        assert client._flow_direct_kep(b"cert", "1234") is True
        assert signer.signed == [nonce.encode()]

    def test_valid_base64_is_decoded(self):
        client, signer = _make_client()
        client.session.post.side_effect = [
            _init_response(base64.b64encode(b"hello").decode()), MagicMock(ok=True)]
        assert client._flow_direct_kep(b"cert", "1234") is True
        assert signer.signed == [b"hello"]


# ─── B8: shared sign-mechanism policy ───────────────────────

class TestChooseSignMechanism:
    def test_known_iit_beats_standard(self):
        assert choose_sign_mechanism([0x00000352, 0x80420032]) == 0x80420032

    def test_known_standard_when_no_iit(self):
        assert choose_sign_mechanism([0x1042, 0x00000352]) == 0x00000352

    def test_vendor_defined_beats_unknown_standard(self):
        assert choose_sign_mechanism([0x1042, 0x80421234]) == 0x80421234

    def test_first_as_last_resort(self):
        assert choose_sign_mechanism([0x1042, 0x1041]) == 0x1042

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            choose_sign_mechanism([])

    def test_virtual_signer_filters_ckf_sign(self, fake_pykcs11, tmp_path):
        from virtual_signer import VirtualSigner
        mod = tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll"
        mod.write_bytes(b"fake")
        fake_pykcs11.MECHS = {
            0x80420031: 0,                       # no CKF_SIGN → ignored
            0x1042: fake_pykcs11.CKF_SIGN,
        }
        assert VirtualSigner(module_path=str(mod))._find_sign_mechanism() == 0x1042

    def test_virtual_signer_no_signing_raises(self, fake_pykcs11, tmp_path):
        from virtual_signer import VirtualSigner
        mod = tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll"
        mod.write_bytes(b"fake")
        fake_pykcs11.MECHS = {0x1042: fake_pykcs11.CKF_VERIFY}
        with pytest.raises(RuntimeError, match="No signing mechanism"):
            VirtualSigner(module_path=str(mod))._find_sign_mechanism()

    def test_pkcs11_signer_uses_shared_policy(self, fake_pykcs11, tmp_path):
        from pkcs11_signer import PKCS11Signer
        mod = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        mod.write_bytes(b"fake")
        fake_pykcs11.MECHS = {
            0x1042: fake_pykcs11.CKF_SIGN,
            0x00000352: fake_pykcs11.CKF_SIGN,
        }
        signer = PKCS11Signer(str(mod))
        assert signer.find_sign_mechanism() == 0x00000352
        assert signer.find_sign_mechanism(prefer_dstu=False) == 0x1042


# ─── B9: default agent port is 8081, not the guessed 9100 ───

class TestDefaultPort:
    def test_client_default_port(self):
        client = IITClient()
        assert client.port == 8081
        assert client.base_url.endswith(":8081/json-rpc")

    @patch("iit_client.requests.options")
    def test_probe_port_default(self, mock_options):
        mock_options.return_value = MagicMock(status_code=200)
        probe_port()
        assert ":8081" in mock_options.call_args.args[0]
