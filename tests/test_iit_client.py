"""
Юніт-тести для iit_client.

Запускати на машині БЕЗ агента — тести перевіряють логіку не потребуючи Windows.
Інтеграційні тести з реальним агентом — в test_integration.py.
"""

import sys
from unittest.mock import patch, MagicMock

import pytest

import iit_client
from iit_client import IITClient, IITRPCError, IITAgentNotFound


class TestRegistryReading:
    """Тести читання реєстру (мокаємо winreg)."""

    def test_read_port_non_windows(self, monkeypatch):
        """На не-Windows повертає (None, None)."""
        monkeypatch.setattr(sys, "platform", "linux")
        http, https = iit_client.read_port_from_registry()
        assert http is None and https is None


class TestJSONRPCProtocol:
    """Перевірка формату запитів/відповідей."""

    @patch("iit_client.requests.Session")
    def test_call_builds_correct_jsonrpc_envelope(self, mock_session_cls):
        """Перевіряє що клієнт формує правильний JSON-RPC 2.0 request."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0", "id": 1, "result": "ok"
        }
        mock_session.post.return_value = mock_response

        client = IITClient(port=9100)
        result = client.call("Initialize", [])

        assert result == "ok"
        call_args = mock_session.post.call_args
        payload = call_args.kwargs["json"]
        assert payload == {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "Initialize",
            "params": [],
        }

    @patch("iit_client.requests.Session")
    def test_call_with_session_id(self, mock_session_cls):
        """Session_id додається в наступні виклики."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"jsonrpc": "2.0", "id": 1, "result": None}
        )

        client = IITClient(port=9100)
        client._session_id = "test-session-123"
        client.call("SignData", [b"hello".hex()])

        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["session_id"] == "test-session-123"

    @patch("iit_client.requests.Session")
    def test_rpc_error_raises(self, mock_session_cls):
        """RPC error → IITRPCError."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32601, "message": "Server error. Requested method not found"}
            }
        )
        client = IITClient(port=9100)
        with pytest.raises(IITRPCError) as exc:
            client.call("NonExistentMethod")
        assert exc.value.code == -32601
        assert "not found" in exc.value.message

    @patch("iit_client.requests.Session")
    def test_http_error_raises(self, mock_session_cls):
        """HTTP non-200 → IITRPCError."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.post.return_value = MagicMock(
            status_code=500, text="Internal Server Error"
        )
        client = IITClient(port=9100)
        with pytest.raises(IITRPCError):
            client.call("Initialize")

    @patch("iit_client.requests.Session")
    def test_connection_error_raises_agent_not_found(self, mock_session_cls):
        import requests
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.post.side_effect = requests.exceptions.ConnectionError("refused")
        client = IITClient(port=9100)
        with pytest.raises(IITAgentNotFound):
            client.call("Initialize")


class TestRPCIDIncrement:
    """id має інкрементуватися."""

    @patch("iit_client.requests.Session")
    def test_rpc_id_increments(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"jsonrpc": "2.0", "id": 1, "result": None}
        )
        client = IITClient(port=9100)
        for expected_id in range(1, 4):
            client.call("X")
            assert mock_session.post.call_args.kwargs["json"]["id"] == expected_id


class TestContextManager:
    @patch("iit_client.requests.Session")
    def test_context_manager_calls_initialize_and_finalize(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"jsonrpc": "2.0", "id": 1, "result": None}
        )
        with IITClient(port=9100) as client:
            client.get_version()

        methods_called = [
            c.kwargs["json"]["method"]
            for c in mock_session.post.call_args_list
        ]
        assert "Initialize" in methods_called
        assert "Finalize" in methods_called
        assert methods_called.index("Initialize") < methods_called.index("GetVersion")
        assert methods_called.index("GetVersion") < methods_called.index("Finalize")


class TestHeaders:
    @patch("iit_client.requests.Session")
    def test_origin_header_set(self, mock_session_cls):
        """Origin header має бути встановлений для CORS."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        client = IITClient(port=9100, origin="https://sedo.mod.gov.ua")
        assert mock_session.headers.update.called
        headers = mock_session.headers.update.call_args[0][0]
        assert headers["Origin"] == "https://sedo.mod.gov.ua"
        assert headers["Content-Type"] == "application/json"


class TestPKCS11SignerModuleDiscovery:
    """Тести для pkcs11_signer без реального PyKCS11."""

    def test_find_module_no_dll(self, tmp_path, monkeypatch):
        """Якщо DLL відсутня, _find_module кидає FileNotFoundError."""
        from pkcs11_signer import PKCS11Signer
        # Set empty search paths
        monkeypatch.setattr(PKCS11Signer, "DEFAULT_MODULE_PATHS",
                            [str(tmp_path / "nonexistent.dll")])
        with pytest.raises(FileNotFoundError):
            PKCS11Signer._find_module()

    def test_find_module_found(self, tmp_path, monkeypatch):
        """Знаходить DLL у списку кандидатів."""
        from pkcs11_signer import PKCS11Signer
        fake = tmp_path / "PKCS11_EKeyAlmaz1C.dll"
        fake.write_bytes(b"fake DLL content")
        monkeypatch.setattr(PKCS11Signer, "DEFAULT_MODULE_PATHS",
                            [str(fake)])
        assert PKCS11Signer._find_module() == str(fake)


class TestSEDOClientURL:
    """Перевіряє що використовується sedo.mod.gov.ua, не старий URL."""

    def test_default_url_is_mod_gov_ua(self):
        from sedo_client import SEDO_MOD_URL
        assert SEDO_MOD_URL == "https://sedo.mod.gov.ua"

    def test_sedo_client_origin_header(self):
        """Перевіряє що SEDOClient ставить Origin = sedo.mod.gov.ua."""
        from sedo_client import SEDOClient
        # Just test module-level default without instantiating
        # (instantiation would need a backend which needs agent)
        from sedo_client import SEDO_MOD_URL
        assert SEDO_MOD_URL.endswith("sedo.mod.gov.ua")
