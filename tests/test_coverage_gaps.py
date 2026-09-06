"""
Tests for code paths the v0.29 audit found uncovered (T5) and for the
shared console helper (T6). All mocked — no agent, no token, no network.
"""

import base64
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

import iit_client
from iit_client import IITClient, IITRPCError, FALLBACK_PORTS, discover_agent
from mechanism_ids import pick_sign_mechanism

ROOT = Path(__file__).resolve().parent.parent


# ─── discover_agent ─────────────────────────────────────────

class TestDiscoverAgent:
    def test_registry_http_port_wins(self):
        with patch("iit_client.read_port_from_registry", return_value=(8081, 8083)), \
             patch("iit_client.probe_port", return_value=True) as probe:
            assert discover_agent() == ("127.0.0.1", 8081, False)
        probe.assert_called_once_with("127.0.0.1", 8081)

    def test_registry_https_port_when_http_dead(self):
        def probe(host, port, use_https=False, **kw):
            return use_https and port == 8083
        with patch("iit_client.read_port_from_registry", return_value=(8081, 8083)), \
             patch("iit_client.probe_port", side_effect=probe):
            assert discover_agent() == ("127.0.0.1", 8083, True)

    def test_fallback_tries_http_then_https_per_port(self):
        """Regression for v0.28: the HTTPS fallback probe used to be dead."""
        def probe(host, port, use_https=False, **kw):
            return use_https and port == 8083
        with patch("iit_client.read_port_from_registry", return_value=(None, None)), \
             patch("iit_client.probe_port", side_effect=probe) as p:
            assert discover_agent() == ("127.0.0.1", 8083, True)
        # 8081 http, 8081 https, 8083 http, 8083 https — in that order
        assert p.call_args_list[:4] == [
            call("127.0.0.1", 8081), call("127.0.0.1", 8081, use_https=True),
            call("127.0.0.1", 8083), call("127.0.0.1", 8083, use_https=True),
        ]

    def test_nothing_found_returns_none(self):
        with patch("iit_client.read_port_from_registry", return_value=(None, None)), \
             patch("iit_client.probe_port", return_value=False) as p:
            assert discover_agent() is None
        assert p.call_count == 2 * len(FALLBACK_PORTS)

    def test_auto_discover_raises_agent_not_found(self):
        with patch("iit_client.discover_agent", return_value=None):
            with pytest.raises(iit_client.IITAgentNotFound):
                IITClient.auto_discover()

    def test_auto_discover_builds_client(self):
        with patch("iit_client.discover_agent", return_value=("127.0.0.1", 8083, True)):
            c = IITClient.auto_discover(origin="https://x")
        assert (c.host, c.port) == ("127.0.0.1", 8083)
        assert c.base_url.startswith("https://")


# ─── sign_data / sign_hash result guards ────────────────────

def _client_returning(result):
    c = IITClient()
    c.call = MagicMock(return_value=result)
    return c


class TestSignResultGuards:
    @pytest.mark.parametrize("method", ["sign_data", "sign_hash"])
    def test_none_result_is_error(self, method):
        with pytest.raises(IITRPCError, match="empty result"):
            getattr(_client_returning(None), method)(b"x")

    @pytest.mark.parametrize("method", ["sign_data", "sign_hash"])
    def test_invalid_base64_is_error(self, method):
        with pytest.raises(IITRPCError, match="invalid base64"):
            getattr(_client_returning("!!not-b64!!"), method)(b"x")

    @pytest.mark.parametrize("method", ["sign_data", "sign_hash"])
    def test_base64_string_decoded(self, method):
        sig = b"\x30\x82" + b"\x01" * 10
        out = getattr(_client_returning(base64.b64encode(sig).decode()), method)(b"x")
        assert out == sig

    def test_sign_data_sends_base64_and_options(self):
        c = _client_returning(base64.b64encode(b"s").decode())
        c.sign_data(b"hello", {"internal": False})
        c.call.assert_called_once_with(
            "SignData", [base64.b64encode(b"hello").decode(), {"internal": False}])


# ─── pick_sign_mechanism ────────────────────────────────────

class TestPickSignMechanism:
    def test_priority_order(self):
        assert pick_sign_mechanism([0x00000352, 0x80420032, 0x80420031]) == 0x80420031
        assert pick_sign_mechanism([0x00000352, 0x80420032]) == 0x80420032
        assert pick_sign_mechanism([0x00000352]) == 0x00000352

    def test_none_when_no_known(self):
        assert pick_sign_mechanism([0x1042, 0x80420014]) is None
        assert pick_sign_mechanism([]) is None

    def test_accepts_non_int_ids(self):
        assert pick_sign_mechanism([str(0x80420031)]) == 0x80420031  # str → int


# ─── _console.force_utf8_io shared by every entry point ─────

class TestConsoleHelper:
    def test_sedo_client_reexports_same_function(self):
        import _console
        import sedo_client
        assert sedo_client.force_utf8_io is _console.force_utf8_io

    @pytest.mark.parametrize("module", [
        "sedo_client.py", "opensc_signer.py", "pkcs11_signer.py",
        "iit_client.py", "scripts/smoke_test.py",
    ])
    def test_no_inline_reconfigure_loops(self, module):
        """Only _console.py may call stream.reconfigure — no more copies."""
        assert "reconfigure(" not in (ROOT / module).read_text(encoding="utf-8")

    def test_opensc_main_calls_helper(self, monkeypatch):
        import sys
        from opensc_signer import main
        monkeypatch.setattr(sys, "argv", ["x", "--module", "m.dll", "--list-slots"])
        fake = MagicMock()
        fake.list_slots.return_value = ""
        with patch("opensc_signer.OpenSCSigner", return_value=fake), \
             patch("_console.force_utf8_io") as f:
            main()
        f.assert_called_once()

    def test_helper_survives_streams_without_reconfigure(self, monkeypatch):
        from _console import force_utf8_io

        class Dummy:
            pass

        monkeypatch.setattr("sys.stdout", Dummy())
        monkeypatch.setattr("sys.stderr", Dummy())
        force_utf8_io()  # must not raise
