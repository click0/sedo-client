"""
Regression tests for the v0.31 P2 core audit: verify-step success, PIN
handling in every CLI, Windows device names, resource release, registry
parsing, unknown-vendor mechanism discovery.

All mocked — no token, no agent, no network.
"""

import inspect
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import iit_client
from iit_client import IITClient
from sedo_client import SEDOClient, _safe_doc_id, _verify_accepted


class _Signer:
    signature_format = "raw"

    def __init__(self):
        self.closed = False
        self.logged_out = False

    def login(self, pin):
        pass

    def get_certificate(self):
        return b"\x30\x82cert"

    def sign(self, data):
        return b"\x00" * 64

    def logout(self):
        self.logged_out = True

    def close(self):
        self.closed = True


def _client(signer=None):
    with patch("sedo_client.SEDOClient._pick_backend", return_value=signer or _Signer()):
        c = SEDOClient()
    c.session = MagicMock()
    return c


def _resp(status, body=None, ctype="application/json"):
    r = MagicMock(status_code=status, ok=200 <= status < 400)
    r.headers = {"Content-Type": ctype} if ctype else {}
    if isinstance(body, Exception):
        r.json.side_effect = body
    else:
        r.json.return_value = body
    return r


def _tool(tmp_path, module_name="PKCS11.EKeyAlmaz1C.dll"):
    tool = tmp_path / "pkcs11-tool"
    tool.write_bytes(b"fake")
    module = tmp_path / module_name
    module.write_bytes(b"fake")
    return str(tool), str(module)


# ─── 1. S4: verify success is not just "status < 400" ──────

class TestVerifyAccepted:
    @pytest.mark.parametrize("resp", [
        _resp(200, {"authenticated": False}),
        _resp(200, {"success": False, "reason": "bad signature"}),
        _resp(200, {"error": "invalid signature"}),
        _resp(302, None, ctype="text/html"),       # redirect back to login
        _resp(200, ValueError("not json")),         # claims JSON, isn't
        _resp(401, {"authenticated": True}),
    ])
    def test_rejections(self, resp):
        assert _verify_accepted(resp) is False

    @pytest.mark.parametrize("resp", [
        _resp(200, {"authenticated": True, "token": "x"}),
        _resp(200, {}),
        _resp(200, [], ctype="application/json"),
        _resp(204, None, ctype=None),
        _resp(200, None, ctype="text/html; charset=utf-8"),
    ])
    def test_acceptances(self, resp):
        assert _verify_accepted(resp) is True

    def test_json_rejection_makes_the_flow_try_the_next_candidate(self):
        """The regression: 200 {"authenticated": false} printed success."""
        c = _client()
        c.session.post.side_effect = [
            _resp(200, {"challenge": "bm9uY2U="}),
            _resp(200, {"authenticated": False}),
            _resp(404), _resp(404),
        ]
        assert c._flow_direct_kep(b"cert") is False


# ─── 2. S5: the flows no longer hold the PIN ───────────────

@pytest.mark.parametrize("name", ["_flow_oidc", "_flow_direct_kep", "_flow_cms_post"])
def test_flows_take_no_pin(name):
    assert "pin" not in inspect.signature(getattr(SEDOClient, name)).parameters


# ─── 3. S6: Windows device names are not file names ────────

class TestWindowsReservedIds:
    @pytest.mark.parametrize("doc_id", [
        "CON", "nul", "Prn", "AUX", "COM1", "lpt9", "NUL.txt", "com3.pdf", "a.",
    ])
    def test_rejected(self, doc_id):
        with pytest.raises(ValueError, match="Unsafe"):
            _safe_doc_id(doc_id)

    @pytest.mark.parametrize("doc_id", [
        "CONTRACT-1", "console", "NULL", "COM10", "doc.42", "LPT", "a.b",
    ])
    def test_ordinary_ids_still_pass(self, doc_id):
        assert _safe_doc_id(doc_id) == doc_id


# ─── 4. D3: an unknown backend is an error, not the IIT agent ─

def test_unknown_backend_raises_before_any_agent_call():
    with patch("iit_client.IITClient.auto_discover") as disc:
        with pytest.raises(ValueError, match="Unknown backend 'pkcs12'"):
            SEDOClient(backend="pkcs12")
    disc.assert_not_called()


# ─── 5. A3: unknown vendor → ask the token, not "IIT by default" ─

LIST_MECHANISMS = b"""\
Using slot 0 with a present token (0x0)
Supported mechanisms:
  mechanism-0x80420014, keySize={32,32}, sign, verify
  mechanism-0x80420021, digest
  mechanism-0x352, keySize={163,509}, hw, sign, verify
  ECDSA, keySize={256,521}, hw, sign, verify
  mechanism-0x80420043, derive
"""


# Verbatim excerpt of `pkcs11-tool --list-mechanisms` on a live Avtor ST-338
# through the IIT copy of Av337CryptokiD.dll (OpenSC 32-bit, 2026-09-24).
REAL_ST338 = """\
Using slot 0 with a present token (0x0)
Supported mechanisms:
  RSA-PKCS, keySize={512,4096}, hw, encrypt, decrypt, sign, verify, wrap, unwrap
  DES-MAC, keySize={8,8}, sign, verify
  SHA256-HMAC, sign, verify
  mechtype-0x252, sign, verify
  ECDSA, keySize={112,521}, hw, sign, verify, EC F_P, EC parameters, EC OID, EC uncompressed
  AES-MAC, keySize={16,32}, sign, verify
  mechtype-0x80420011, keySize={32,32}, encrypt, decrypt, unwrap
  mechtype-0x80420014, keySize={32,32}, sign, verify
  mechtype-0x80420015, keySize={32,32}, sign, verify
  mechtype-0x80420016, keySize={32,32}, wrap, unwrap
  mechtype-0x80420021, digest
  mechtype-0x80420031, keySize={163,509}, hw, sign, verify, EC F_2M, EC parameters, EC OID, EC compressed
  mechtype-0x80420032, keySize={163,509}, hw, sign, verify, EC F_2M, EC parameters, EC OID, EC compressed
  mechtype-0x80420042, keySize={163,509}, hw, generate_key_pair, EC F_2M, EC parameters, EC OID, EC compressed
"""


class TestRealPkcs11ToolOutput:
    def test_real_format_is_parsed(self):
        """The regression: the parser matched 'mechanism-0x', OpenSC prints 'mechtype-0x'."""
        from opensc_signer import parse_sign_mechanisms
        assert parse_sign_mechanisms(REAL_ST338.splitlines()) == [
            0x252, 0x80420014, 0x80420015, 0x80420031, 0x80420032]

    def test_real_list_chooses_dstu_not_a_mac(self):
        from mechanism_ids import choose_sign_mechanism
        from opensc_signer import parse_sign_mechanisms
        ids = parse_sign_mechanisms(REAL_ST338.splitlines())
        assert choose_sign_mechanism(ids) == 0x80420031

    def test_second_mac_is_never_chosen(self):
        from mechanism_ids import NON_SIGNATURE_MECHANISMS, choose_sign_mechanism
        assert 0x80420015 in NON_SIGNATURE_MECHANISMS
        assert choose_sign_mechanism([0x80420014, 0x80420015, 0x80421234]) == 0x80421234


class TestUnknownVendorMechanism:
    def test_parse_sign_mechanisms(self):
        from opensc_signer import parse_sign_mechanisms
        ids = parse_sign_mechanisms(LIST_MECHANISMS.decode().splitlines())
        assert ids == [0x80420014, 0x352]

    def test_sign_recover_is_not_sign(self):
        from opensc_signer import parse_sign_mechanisms
        assert parse_sign_mechanisms(["  mechanism-0x1234, signRecover"]) == []

    def _build(self, tmp_path, module_name, stdout=LIST_MECHANISMS, rc=0):
        tool, module = _tool(tmp_path, module_name)
        calls = []

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=b"boom")

        with patch("opensc_signer.OpenSCSigner._find_tool", return_value=tool), \
             patch("opensc_signer.subprocess.run", side_effect=fake_run):
            c = SEDOClient(backend="opensc", module_path=module)
        return c.signer, calls

    def test_unknown_module_uses_the_tokens_dstu_mechanism(self, tmp_path):
        """The regression: opensc-pkcs11.so got 0x80420031 → CKR_MECHANISM_INVALID."""
        signer, calls = self._build(tmp_path, "opensc-pkcs11.so")
        assert signer._mechanism == "0x00000352"   # SYM_MAC skipped, DSTU chosen
        assert calls and "--list-mechanisms" in calls[0]
        assert "--pin" not in calls[0]              # no PIN attempt spent

    def test_known_vendor_is_also_decided_by_the_token(self, tmp_path):
        """Even a known module name is only a fallback: ST-338 proved it wrong."""
        signer, calls = self._build(tmp_path, "Av337CryptokiD.dll",
                                    stdout=REAL_ST338.encode())
        assert signer._mechanism == "0x80420031"
        assert calls and "--list-mechanisms" in calls[0] and "--pin" not in calls[0]

    def test_query_failure_falls_back_with_a_warning(self, tmp_path, caplog):
        signer, _ = self._build(tmp_path, "vendor-x.dll", rc=1)
        assert signer._mechanism == "0x80420031"
        assert "No usable mechanism list" in caplog.text


def test_32bit_opensc_is_found_first():
    from opensc_signer import OpenSCSigner
    paths = OpenSCSigner.DEFAULT_PKCS11_TOOL_PATHS
    x86 = next(i for i, p in enumerate(paths) if "(x86)" in p)
    x64 = next(i for i, p in enumerate(paths) if p.startswith(r"C:\Program Files\OpenSC"))
    assert x86 < x64


# ─── 6. C7: resources are released at the end ──────────────

class TestResourceRelease:
    def test_sedo_client_exit_closes_the_backend(self):
        signer = _Signer()
        c = _client(signer)
        c.__exit__(None, None, None)
        assert signer.logged_out and signer.closed
        c.session.close.assert_called_once()

    def test_backend_without_close_is_fine(self):
        class Old(_Signer):
            close = None
        c = _client(Old())
        c.__exit__(None, None, None)
        c.session.close.assert_called_once()

    def test_iit_client_exit_closes_http_session(self):
        with patch("iit_client.requests.Session") as S:
            c = IITClient()
        c.call = MagicMock()
        with c:
            pass
        S.return_value.close.assert_called_once()

    def test_iit_adapter_close_closes_client(self):
        from sedo_client import IITAgentAdapter
        client = MagicMock()
        IITAgentAdapter(client).close()
        client.close.assert_called_once()

    def test_finalize_uses_reset_private_key(self):
        with patch("iit_client.requests.Session"):
            c = IITClient()
        c.call = MagicMock()
        c.reset_private_key = MagicMock()
        c.finalize()
        c.reset_private_key.assert_called_once()

    def test_pkcs11_close_unloads_the_module(self, fake_pykcs11, tmp_path):
        from pkcs11_signer import PKCS11Signer
        dll = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        dll.write_bytes(b"x")
        fake_pykcs11.MECHS = {0x80420031: fake_pykcs11.CKF_SIGN}
        with PKCS11Signer(str(dll)) as s:
            s.login("1234")
        assert fake_pykcs11.SESSIONS[0].closed
        assert fake_pykcs11.UNLOADS == [str(dll)]

    def test_virtual_close_unloads_the_module(self, fake_pykcs11, tmp_path):
        from virtual_signer import VirtualSigner
        dll = tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll"
        dll.write_bytes(b"x")
        s = VirtualSigner(module_path=str(dll))
        s.close()
        assert fake_pykcs11.UNLOADS == [str(dll)]

    @pytest.mark.parametrize("cls_path", ["pkcs11_signer.PKCS11Signer",
                                          "virtual_signer.VirtualSigner"])
    def test_failed_init_does_not_leave_the_module_loaded(self, fake_pykcs11,
                                                          tmp_path, cls_path):
        import importlib
        mod_name, cls_name = cls_path.split(".")
        cls = getattr(importlib.import_module(mod_name), cls_name)
        dll = tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll"
        dll.write_bytes(b"x")
        fake_pykcs11.GETINFO_ERROR = RuntimeError("CKR_GENERAL_ERROR")
        with pytest.raises(RuntimeError):
            cls(module_path=str(dll))
        assert fake_pykcs11.UNLOADS == [str(dll)]


# ─── 7. C9 / C10: registry readers ─────────────────────────

def _fake_winreg(values=None, open_error=None):
    w = types.ModuleType("winreg")
    w.HKEY_LOCAL_MACHINE, w.HKEY_CURRENT_USER = 1, 2
    w.KEY_READ, w.KEY_WOW64_32KEY = 0x20019, 0x200

    class _Key:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def OpenKey(hive, path, reserved, access):
        if open_error is not None:
            raise open_error
        return _Key()

    def QueryValueEx(key, name):
        if values is None or name not in values:
            raise FileNotFoundError(name)
        return values[name], 1

    def EnumKey(key, i):
        raise OSError("no more")

    w.OpenKey, w.QueryValueEx, w.EnumKey = OpenKey, QueryValueEx, EnumKey
    return w


class TestRegistry:
    def test_trusted_sites_permission_error_is_not_a_crash(self, monkeypatch):
        """The regression: PermissionError escaped `--discover`."""
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setitem(sys.modules, "winreg",
                            _fake_winreg(open_error=PermissionError("denied")))
        assert iit_client.read_trusted_sites() == []

    def test_reg_sz_port_becomes_int(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setitem(sys.modules, "winreg",
                            _fake_winreg({"HTTPPort": "8081", "HTTPSPort": " 8083 "}))
        assert iit_client.read_port_from_registry() == (8081, 8083)

    @pytest.mark.parametrize("raw,port", [
        (8081, 8081), ("8081", 8081), ("0x1F91", 8081), ("08081", 8081),
        ("abc", None), (0, None), (70000, None), (None, None),
    ])
    def test_as_port(self, raw, port):
        assert iit_client._as_port(raw) == port


# ─── 8. C11: an empty PIN never reaches the token ──────────

class TestEmptyPin:
    def test_read_pin_order(self, monkeypatch):
        from _console import read_pin
        monkeypatch.setenv("SEDO_PIN", "env")
        assert read_pin("argv") == "argv"
        assert read_pin(None) == "env"
        monkeypatch.delenv("SEDO_PIN")
        with patch("getpass.getpass", return_value="typed"):
            assert read_pin(None) == "typed"

    @pytest.mark.parametrize("prompt", [
        {"return_value": ""}, {"side_effect": EOFError},
    ])
    def test_read_pin_empty_exits(self, monkeypatch, prompt):
        from _console import read_pin
        monkeypatch.delenv("SEDO_PIN", raising=False)
        with patch("getpass.getpass", **prompt), pytest.raises(SystemExit) as e:
            read_pin(None)
        assert e.value.code == 2

    def test_opensc_cli_empty_pin_does_not_exit_zero(self, tmp_path, monkeypatch):
        """The regression: Enter at the prompt → --sign skipped, exit 0."""
        from opensc_signer import main
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("SEDO_PIN", raising=False)
        (tmp_path / "d.bin").write_bytes(b"x")
        monkeypatch.setattr(sys, "argv", ["opensc_signer", "--module", "m.dll",
                                          "--sign", "d.bin"])
        fake = MagicMock()
        with patch("opensc_signer.OpenSCSigner", return_value=fake), \
             patch("getpass.getpass", return_value=""), \
             pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 2
        fake.login.assert_not_called()
        fake.sign.assert_not_called()

    def test_opensc_cli_reads_sedo_pin(self, tmp_path, monkeypatch):
        from opensc_signer import main
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("SEDO_PIN", "4321")
        monkeypatch.setattr(sys, "argv", ["opensc_signer", "--module", "m.dll",
                                          "--list-objects"])
        fake = MagicMock()
        fake.list_objects.return_value = "objects"
        with patch("opensc_signer.OpenSCSigner", return_value=fake), \
             patch("getpass.getpass") as gp:
            main()
        gp.assert_not_called()
        fake.login.assert_called_once_with("4321")

    def test_sedo_client_empty_pin_never_builds_a_client(self, tmp_path, monkeypatch):
        from sedo_client import main
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("SEDO_PIN", raising=False)
        monkeypatch.setattr(sys, "argv", ["sedo-client"])
        with patch("sedo_client.SEDOClient") as cls, \
             patch("getpass.getpass", return_value=""), \
             pytest.raises(SystemExit):
            main()
        cls.assert_not_called()

    def test_pkcs11_cli_empty_pin_never_logs_in(self, tmp_path, monkeypatch):
        import pkcs11_signer
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("SEDO_PIN", raising=False)
        (tmp_path / "d.bin").write_bytes(b"x")
        monkeypatch.setattr(sys, "argv", ["pkcs11_signer", "--module", "m.dll",
                                          "--sign", "d.bin"])
        fake = MagicMock()
        with patch("pkcs11_signer.PKCS11Signer", return_value=fake), \
             patch("getpass.getpass", return_value=""), \
             pytest.raises(SystemExit):
            pkcs11_signer.main()
        fake.login.assert_not_called()


# ─── 9. A1: every backend declares what sign() returns ─────

def test_signature_formats_are_declared():
    from opensc_signer import OpenSCSigner
    from pkcs11_signer import PKCS11Signer
    from sedo_client import IITAgentAdapter
    from virtual_signer import VirtualSigner
    assert OpenSCSigner.signature_format == "raw"
    assert PKCS11Signer.signature_format == "raw"
    assert VirtualSigner.signature_format == "raw"
    assert IITAgentAdapter.signature_format == "cms"


def test_non_object_documents_are_skipped(tmp_path, monkeypatch):
    from sedo_client import main
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["sedo-client", "--pin", "1", "--fetch",
                                      "--output", str(tmp_path / "out")])
    fake_ctx = MagicMock()
    sedo = fake_ctx.__enter__.return_value
    sedo.fetch_inbox.return_value = ["junk", {"id": "doc-1"}]
    sedo.download_document.return_value = Path("doc-1.zip")
    with patch("sedo_client.SEDOClient", return_value=fake_ctx):
        main()
    sedo.download_document.assert_called_once()
