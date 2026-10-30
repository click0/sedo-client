"""
Agent transport details confirmed from the "Параметри роботи" dialog of
«Користувач ЦСК»: Origin matched exactly against TrustedSites, AutoRun of the
agent process, and the per-machine "EU Sign Agent CA" behind the HTTPS port.
All mocked — no agent, no network.
"""

import logging
import ssl
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
import requests

from sedo import iit_client
from sedo.iit_client import IITClient, IITAgentNotFound, origin_from_url, probe_port, verify_agent

DER = b"\x30\x82\x01\x00" + bytes(range(256))      # any bytes: DER→PEM is a pure re-encoding


@pytest.fixture
def no_ca(monkeypatch, tmp_path):
    """No CA anywhere: env unset, no registry, default dirs empty."""
    monkeypatch.delenv(iit_client.AGENT_CA_ENV, raising=False)
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    monkeypatch.setattr(iit_client, "AGENT_CA_DIRS", [str(ca_dir)])
    monkeypatch.setattr(iit_client, "_query_values", lambda path, names: {})
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache"))
    return ca_dir


@pytest.fixture
def with_ca(no_ca):
    ca = no_ca / "EUSignAgentCA.cer"
    ca.write_bytes(DER)
    return ca


class TestOrigin:
    @pytest.mark.parametrize("url,origin", [
        ("https://sedo.mod.gov.ua", "https://sedo.mod.gov.ua"),
        ("https://sedo.mod.gov.ua/", "https://sedo.mod.gov.ua"),
        ("https://sedo.mod.gov.ua/some/path?x=1", "https://sedo.mod.gov.ua"),
        (" https://sedo.mod.gov.ua/ ", "https://sedo.mod.gov.ua"),
        ("http://127.0.0.1:8000/", "http://127.0.0.1:8000"),
        ("not-a-url/", "not-a-url"),
    ])
    def test_origin_from_url(self, url, origin):
        assert origin_from_url(url) == origin

    def test_client_normalises_origin_header(self):
        c = IITClient(origin="https://sedo.mod.gov.ua/")
        assert c.origin == "https://sedo.mod.gov.ua"
        assert c.session.headers["Origin"] == "https://sedo.mod.gov.ua"


class TestAutoRun:
    def _reg(self, monkeypatch, values):
        from test_p2_core import _fake_winreg
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setitem(sys.modules, "winreg", _fake_winreg(values))

    @pytest.mark.parametrize("raw,expected", [
        (0, False), (1, True), ("0", False), ("1", True), ("true", True), ("x", None),
    ])
    def test_values(self, monkeypatch, raw, expected):
        self._reg(monkeypatch, {"AutoRun": raw})
        assert iit_client.read_agent_autorun() is expected

    def test_missing_is_unknown(self, monkeypatch):
        self._reg(monkeypatch, {"HTTPPort": 8081})
        assert iit_client.read_agent_autorun() is None

    def test_not_windows(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert iit_client.read_agent_autorun() is None


class TestCaFiles:
    def test_nothing_found(self, no_ca):
        assert iit_client.agent_ca_files() == []
        assert iit_client.agent_ca_bundle() is None

    def test_default_dir(self, with_ca):
        assert iit_client.agent_ca_files() == [with_ca]

    def test_env_first_and_missing_env_warns(self, with_ca, monkeypatch, caplog):
        mine = with_ca.parent / "my.pem"
        mine.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", encoding="utf-8")
        monkeypatch.setenv(iit_client.AGENT_CA_ENV, str(mine))
        assert iit_client.agent_ca_files() == [mine, with_ca]
        monkeypatch.setenv(iit_client.AGENT_CA_ENV, str(with_ca.parent / "gone.pem"))
        with caplog.at_level(logging.WARNING, logger="sedo.iit_client"):
            assert iit_client.agent_ca_files() == [with_ca]
        assert "gone.pem" in caplog.text and "does not exist" in caplog.text

    def test_registry_path(self, no_ca, monkeypatch):
        f = no_ca / "FromRegistry.cer"
        f.write_bytes(DER)
        monkeypatch.setattr(iit_client, "_query_values",
                            lambda path, names: {"SSLCertPath": str(f), "Other": 1})
        assert iit_client.agent_ca_files() == [f]

    def test_bundle_converts_der_and_dedupes(self, with_ca, monkeypatch):
        pem_text = ssl.DER_cert_to_PEM_cert(DER)
        twin = with_ca.parent / "EUSignAgent.pem"
        twin.write_text(pem_text, encoding="utf-8")        # same cert, PEM form
        bundle = iit_client.agent_ca_bundle()
        assert bundle.endswith("agent-ca.pem") and "cache" in bundle
        content = open(bundle, encoding="utf-8").read()
        assert content == pem_text                          # one copy, not two
        first_mtime = __import__("os").stat(bundle).st_mtime_ns
        assert iit_client.agent_ca_bundle() == bundle       # unchanged → not rewritten
        assert __import__("os").stat(bundle).st_mtime_ns == first_mtime

    def test_unwritable_cache_means_unverified(self, with_ca, monkeypatch, caplog):
        monkeypatch.setattr(iit_client, "_bundle_dir",
                            lambda env=None: with_ca)       # a file, not a directory
        with caplog.at_level(logging.WARNING, logger="sedo.iit_client"):
            assert iit_client.agent_ca_bundle() is None
        assert "TLS stays unverified" in caplog.text


class TestVerifyChoice:
    def test_plain_http_and_remote_https(self, with_ca):
        assert iit_client._tls_verify("127.0.0.1", False) is True
        assert iit_client._tls_verify("10.0.0.5", True) is True     # never the agent bundle

    def test_loopback_without_ca(self, no_ca):
        assert iit_client._tls_verify("127.0.0.1", True) is False
        assert IITClient(port=8083, use_https=True).session.verify is False

    def test_loopback_with_ca(self, with_ca):
        v = iit_client._tls_verify("localhost", True)
        assert isinstance(v, str) and v.endswith("agent-ca.pem")
        assert IITClient(port=8083, use_https=True).session.verify == v


class TestFallback:
    def _ssl_then_ok(self, calls):
        def send(url, **kw):
            calls.append(kw["verify"])
            if isinstance(kw["verify"], str):
                raise requests.exceptions.SSLError("hostname mismatch")
            return MagicMock(status_code=200,
                             json=lambda: {"jsonrpc": "2.0", "id": 0, "result": "1.3.1"})
        return send

    def test_probe_and_verify_retry_unverified(self, with_ca):
        calls = []
        with patch("sedo.iit_client.requests.options", side_effect=self._ssl_then_ok(calls)), \
             patch("sedo.iit_client.requests.post", side_effect=self._ssl_then_ok(calls)):
            assert probe_port("127.0.0.1", 8083, use_https=True) is True
            assert verify_agent("127.0.0.1", 8083, use_https=True) is True
        assert [isinstance(v, str) for v in calls] == [True, False, True, False]

    def test_remote_ssl_error_is_not_retried(self, with_ca):
        with patch("sedo.iit_client.requests.options",
                   side_effect=requests.exceptions.SSLError("bad")) as opt:
            assert probe_port("10.0.0.5", 8083, use_https=True) is False
        assert opt.call_count == 1

    def test_client_falls_back_once_and_reports(self, with_ca, caplog):
        c = IITClient(port=8083, use_https=True)
        bundle = c.session.verify
        assert isinstance(bundle, str)
        seen = []

        def post(url, **kw):
            seen.append(c.session.verify)
            if isinstance(c.session.verify, str):
                raise requests.exceptions.SSLError("IP address mismatch")
            return MagicMock(status_code=200,
                             json=lambda: {"jsonrpc": "2.0", "id": 1, "result": "1.3.1"})
        c.session.post = post
        with caplog.at_level(logging.WARNING, logger="sedo.iit_client"):
            assert c.get_version() == "1.3.1"
            assert c.get_version() == "1.3.1"
        assert seen == [bundle, False, False]
        assert "IP address mismatch" in c.tls_fallback
        assert caplog.text.count("continuing without certificate verification") == 1

    def test_client_without_bundle_raises(self, no_ca):
        c = IITClient(port=8083, use_https=True)
        c.session.post = MagicMock(side_effect=requests.exceptions.SSLError("bad"))
        with pytest.raises(IITAgentNotFound):
            c.get_version()
        assert c.tls_fallback is None


class TestCheckAgent:
    """sedo.check._check_agent on a fake client."""

    def _run(self, monkeypatch, *, https, autorun, trusted, verify="bundle.pem",
             fallback=None, url="https://sedo.mod.gov.ua/"):
        from sedo import check as chk
        from sedo.config import KeyProfile

        class _Client:
            def __init__(self, **kw):
                self.origin = origin_from_url(kw["origin"])
                self.session = types.SimpleNamespace(verify=verify)
                self.tls_fallback = fallback

            def get_version(self):
                return "1.3.1"

            def close(self):
                pass

        monkeypatch.setattr(iit_client, "discover_agent", lambda: ("127.0.0.1", 8083 if https else 8081, https))
        monkeypatch.setattr(iit_client, "read_agent_autorun", lambda: autorun)
        monkeypatch.setattr(iit_client, "read_trusted_sites", lambda: trusted)
        monkeypatch.setattr(iit_client, "IITClient", _Client)
        rep = chk.Report()
        chk.check_profile(KeyProfile("a", backend="iit_agent"), url, True, rep)
        return rep, rep.render()

    def test_http_all_good(self, monkeypatch):
        rep, text = self._run(monkeypatch, https=False, autorun=True,
                              trusted=["https://sedo.mod.gov.ua", "https://id.gov.ua"])
        assert "автозапуск" not in text and "TLS" not in text
        assert "Origin https://sedo.mod.gov.ua (з url https://sedo.mod.gov.ua/)" in text
        assert "версія 1.3.1" in text
        assert rep.problems == 2                            # cert_index note + no PIN env

    def test_autorun_off_and_origin_missing(self, monkeypatch):
        rep, text = self._run(monkeypatch, https=False, autorun=False,
                              trusted=["https://id.gov.ua"])
        assert "автозапуск агента вимкнено (AutoRun = 0)" in text
        assert "Origin https://sedo.mod.gov.ua немає серед довірених" in text

    def test_https_verified(self, monkeypatch):
        _, text = self._run(monkeypatch, https=True, autorun=None, trusted=[])
        assert "✓ TLS перевірено за bundle.pem" in text

    def test_https_fallback_and_no_ca(self, monkeypatch):
        _, text = self._run(monkeypatch, https=True, autorun=None, trusted=[],
                            fallback="IP address mismatch")
        assert "! TLS: CA агента не підійшов" in text and "IP address mismatch" in text
        _, text = self._run(monkeypatch, https=True, autorun=None, trusted=[], verify=False)
        assert "! TLS без перевірки сертифіката" in text and "SEDO_AGENT_CA" in text
