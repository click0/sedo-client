"""
Regression tests for the v0.31 P0 PIN-safety audit.

Every test here guards a way the PIN could leak, or a way the Almaz-1K's
15-attempt counter could be spent faster than the docs promise. All mocked:
no token, no network, no subprocess.
"""

import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

import iit_client
from iit_client import IITClient, IITRPCError, discover_agent, verify_agent
from mechanism_ids import NON_SIGNATURE_MECHANISMS, choose_sign_mechanism
from opensc_signer import OpenSCSigner

ROOT = Path(__file__).resolve().parent.parent
PIN = "9876"


def _opensc(tmp_path):
    tool = tmp_path / "pkcs11-tool"
    tool.write_bytes(b"fake")
    module = tmp_path / "PKCS11.dll"
    module.write_bytes(b"fake")
    s = OpenSCSigner(module_path=str(module), pkcs11_tool=str(tool))
    s.login(PIN)
    return s


# ─── 1. PIN must not survive a subprocess timeout ───────────

class TestTimeoutDoesNotLeakPin:
    @patch("opensc_signer.subprocess.run")
    def test_timeout_message_is_redacted(self, mock_run, tmp_path):
        signer = _opensc(tmp_path)
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["pkcs11-tool", "--login", "--pin", PIN, "--sign"], timeout=30.0)
        with pytest.raises(subprocess.TimeoutExpired) as exc:
            signer.sign(b"payload")
        text = str(exc.value)
        assert PIN not in text
        assert "***" in text
        # The whole exception chain must be PIN-free: the original TimeoutExpired
        # carries the raw argv in its own repr, so it must not be reachable at all.
        chain, seen = exc.value, 0
        while chain is not None and seen < 10:
            assert PIN not in str(chain), f"PIN reachable via chain: {chain!r}"
            chain = chain.__cause__ or chain.__context__
            seen += 1

    @patch("opensc_signer.subprocess.run")
    def test_timeout_keeps_type_and_timeout_value(self, mock_run, tmp_path):
        signer = _opensc(tmp_path)
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["pkcs11-tool", "--pin", PIN], timeout=12.5, output=b"o", stderr=b"e")
        with pytest.raises(subprocess.TimeoutExpired) as exc:
            signer.get_certificate()
        assert exc.value.timeout == 12.5
        assert exc.value.output == b"o" and exc.value.stderr == b"e"

    @patch("opensc_signer.subprocess.run")
    def test_pin_absent_from_every_log_record(self, mock_run, tmp_path, caplog):
        import logging
        signer = _opensc(tmp_path)
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=b"", stderr=b"CKR_PIN_INCORRECT")
        with caplog.at_level(logging.DEBUG, logger="opensc_signer"):
            with pytest.raises(RuntimeError):
                signer.sign(b"x")
        assert PIN not in caplog.text


# ─── 2. Agent discovery must identify the agent before any PIN ──

class TestAgentDiscoveryVerifies:
    @patch("iit_client.requests.post")
    def test_verify_accepts_jsonrpc_result(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"jsonrpc": "2.0", "id": 0, "result": "1.3.1"})
        assert verify_agent("127.0.0.1", 8081) is True
        # The probe itself must never carry a PIN.
        assert "pin" not in str(mock_post.call_args).lower()

    @patch("iit_client.requests.post")
    def test_verify_accepts_jsonrpc_error(self, mock_post):
        """An agent that lacks GetVersion still proves it is a JSON-RPC server."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"jsonrpc": "2.0", "id": 0,
                          "error": {"code": -32601, "message": "not found"}})
        assert verify_agent("127.0.0.1", 8081) is True

    @pytest.mark.parametrize("body,status", [
        ({"ok": True}, 200),               # a foreign service with a JSON API
        ([], 200),                         # non-dict
        ("plain", 200),                    # non-dict
        ({"jsonrpc": "1.0", "result": 1}, 200),   # wrong envelope version
        ({"jsonrpc": "2.0", "result": 1}, 404),   # right shape, wrong status
    ])
    @patch("iit_client.requests.post")
    def test_verify_rejects_foreign_service(self, mock_post, body, status):
        mock_post.return_value = MagicMock(status_code=status, json=lambda: body)
        assert verify_agent("127.0.0.1", 8080) is False

    @patch("iit_client.requests.post")
    def test_verify_rejects_html(self, mock_post):
        resp = MagicMock(status_code=200)
        resp.json.side_effect = ValueError("no json")
        mock_post.return_value = resp
        assert verify_agent("127.0.0.1", 8080) is False

    @patch("iit_client.requests.post", side_effect=requests.exceptions.ConnectionError)
    def test_verify_rejects_dead_port(self, _mock_post):
        assert verify_agent("127.0.0.1", 9999) is False

    def test_discover_skips_a_port_that_answers_but_is_not_the_agent(self):
        """The regression: 8080 answers OPTIONS, so discovery used to pick it."""
        with patch("iit_client.read_port_from_registry", return_value=(None, None)), \
             patch("iit_client.probe_port", return_value=True), \
             patch("iit_client.verify_agent",
                   side_effect=lambda h, p, **kw: p == 8083) as ver:
            assert discover_agent() == ("127.0.0.1", 8083, False)
        assert ver.called

    def test_discover_returns_none_when_nothing_verifies(self):
        with patch("iit_client.read_port_from_registry", return_value=(8081, 8083)), \
             patch("iit_client.probe_port", return_value=True), \
             patch("iit_client.verify_agent", return_value=False):
            assert discover_agent() is None

    def test_registry_port_is_also_verified(self):
        with patch("iit_client.read_port_from_registry", return_value=(8081, None)), \
             patch("iit_client.probe_port", return_value=True), \
             patch("iit_client.verify_agent", return_value=False) as ver:
            assert discover_agent() is None
        assert ver.called


# ─── 3. The HTTP error body must be redacted for PIN methods ──

class TestErrorBodyRedaction:
    def _client_returning(self, status, text):
        with patch("iit_client.requests.Session") as S:
            sess = MagicMock()
            S.return_value = sess
            resp = MagicMock(status_code=status, text=text)
            resp.json.side_effect = ValueError("not json")
            sess.post.return_value = resp
            return IITClient()

    def test_non_200_body_redacted_for_pin_method(self):
        echoed = f'{{"method":"ReadPrivateKey","params":[{{}},"{PIN}"]}}'
        client = self._client_returning(400, echoed)
        with pytest.raises(IITRPCError) as exc:
            client.read_private_key({"devIndex": 0}, PIN)
        assert PIN not in str(exc.value)
        assert "[***]" in str(exc.value)

    def test_non_json_body_redacted_for_pin_method(self):
        echoed = f'<html>params: {PIN}</html>'
        client = self._client_returning(200, echoed)
        with pytest.raises(IITRPCError) as exc:
            client.read_private_key({"devIndex": 0}, PIN)
        assert PIN not in str(exc.value)
        assert "[***]" in str(exc.value)

    def test_body_still_shown_for_harmless_method(self):
        client = self._client_returning(500, "upstream exploded")
        with pytest.raises(IITRPCError, match="upstream exploded"):
            client.call("GetVersion")

    def test_every_redacted_method_is_covered(self):
        """Whatever is in _REDACTED_METHODS must also gate the error body."""
        for method in iit_client._REDACTED_METHODS:
            client = self._client_returning(400, f"echo {PIN}")
            with pytest.raises(IITRPCError) as exc:
                client.call(method, [{}, PIN])
            assert PIN not in str(exc.value), method


# ─── 4. A symmetric MAC must never be offered as a signature ──

class TestMacMechanismNeverChosen:
    def test_mac_is_on_the_deny_list(self):
        assert 0x80420014 in NON_SIGNATURE_MECHANISMS

    def test_known_dstu_still_wins(self):
        assert choose_sign_mechanism([0x80420014, 0x80420031]) == 0x80420031
        assert choose_sign_mechanism([0x80420014, 0x00000352]) == 0x00000352

    def test_mac_skipped_in_vendor_tier(self):
        """The regression: 0x80420014 sorts first and is >= 0x80000000."""
        assert choose_sign_mechanism([0x80420014, 0x80421234]) == 0x80421234

    def test_mac_skipped_in_last_resort_tier(self):
        assert choose_sign_mechanism([0x80420014, 0x1042]) == 0x1042

    def test_mac_only_raises_instead_of_returning_a_mac(self):
        with pytest.raises(ValueError, match="only non-signature"):
            choose_sign_mechanism([0x80420014])

    def test_empty_still_raises(self):
        with pytest.raises(ValueError, match="no signing mechanisms"):
            choose_sign_mechanism([])

    def test_pkcs11_find_sign_mechanism_reports_runtimeerror(self, fake_pykcs11, tmp_path):
        from pkcs11_signer import PKCS11Signer
        mod = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        mod.write_bytes(b"fake")
        fake_pykcs11.MECHS = {0x80420014: fake_pykcs11.CKF_SIGN}
        signer = PKCS11Signer(str(mod))
        with pytest.raises(RuntimeError, match="No DSTU 4145 signing mechanism"):
            signer.find_sign_mechanism()

    def test_virtual_find_sign_mechanism_reports_runtimeerror(self, fake_pykcs11, tmp_path):
        from virtual_signer import VirtualSigner
        mod = tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll"
        mod.write_bytes(b"fake")
        fake_pykcs11.MECHS = {0x80420014: fake_pykcs11.CKF_SIGN}
        with pytest.raises(RuntimeError, match="No signing mechanism"):
            VirtualSigner(module_path=str(mod))._find_sign_mechanism()


# ─── 5. opensc_signer CLI must stop after the first PIN failure ──

class TestOpenSCCliStopsOnPinFailure:
    def test_list_objects_raises_instead_of_returning_empty(self, tmp_path):
        with patch("opensc_signer.subprocess.run") as mock_run:
            signer = _opensc(tmp_path)
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout=b"", stderr=b"CKR_PIN_INCORRECT")
            with pytest.raises(RuntimeError, match="list-objects failed"):
                signer.list_objects()

    def test_cli_spends_one_attempt_not_three(self, tmp_path, monkeypatch):
        """--list-objects --get-cert --sign used to run three --login calls."""
        import sys
        from opensc_signer import main
        monkeypatch.chdir(tmp_path)
        (tmp_path / "data.bin").write_bytes(b"payload")
        monkeypatch.setattr(sys, "argv", [
            "opensc_signer", "--module", "m.dll", "--pin", PIN,
            "--list-objects", "--get-cert", "--sign", "data.bin"])
        fake = MagicMock()
        fake.list_objects.side_effect = RuntimeError("list-objects failed: CKR_PIN_INCORRECT")
        with patch("opensc_signer.OpenSCSigner", return_value=fake):
            with pytest.raises(RuntimeError, match="list-objects failed"):
                main()
        fake.get_certificate.assert_not_called()
        fake.sign.assert_not_called()


# ─── 6. opensc-test-almaz.ps1 must abort on a failed login ──

class TestPowerShellScriptPinBudget:
    @staticmethod
    def _script() -> str:
        return (ROOT / "opensc-test-almaz.ps1").read_bytes().decode("cp1251")

    def test_aborts_after_a_failed_login(self):
        src = self._script()
        idx = src.index("--list-objects")
        after = src[idx:idx + 600]
        assert "$LASTEXITCODE -ne 0" in after
        assert "exit 1" in after

    def test_only_one_mechanism_unless_all_requested(self):
        src = self._script()
        assert "[switch]$AllMechanisms" in src
        start = src.index("$mechanisms = @(")
        default_list = src[start:src.index(")", start)]
        assert "0x80420031" in default_list
        # The alternates must be behind the switch, not in the default list.
        assert "0x80420032" not in default_list
        assert "0x00000352" not in default_list
        guarded = src[src.index(")", start):src.index("foreach ($m in $mechanisms)")]
        assert "if ($AllMechanisms)" in guarded
        assert "0x80420032" in guarded and "0x00000352" in guarded

    def test_banner_no_longer_promises_one_signature_unconditionally(self):
        src = self._script()
        assert "Буде виконано до 3 спроб" in src

    def test_version_matches_the_package(self):
        import re as _re
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        version = _re.search(r'^version = "([^"]+)"', pyproject, _re.M).group(1)
        assert f"# Version:  {version}" in self._script()


# ─── Cross-cutting: no PIN in any user-visible failure ──

class TestNoPinInUserVisibleErrors:
    @patch("opensc_signer.subprocess.run")
    def test_sign_failure_message_has_no_pin(self, mock_run, tmp_path):
        signer = _opensc(tmp_path)
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=b"", stderr=b"error: PIN incorrect")
        with pytest.raises(RuntimeError) as exc:
            signer.sign(b"x")
        assert PIN not in str(exc.value)

    def test_redacted_methods_set_is_not_empty(self):
        assert iit_client._REDACTED_METHODS
        assert "ReadPrivateKey" in iit_client._REDACTED_METHODS
