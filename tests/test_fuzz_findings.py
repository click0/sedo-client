"""
Regressions for what the fuzzing round before 0.37 found.

Each harness fed one parser of foreign data — SEDO responses, the IIT agent,
pkcs11-tool output, config and PIN files, the report summary, PE headers —
with generated input and checked a property, not only "does not crash". Every
test here is the smallest input that broke one.
"""

import codecs
import http.client
import io
import json
import logging
import struct
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import pytest
import requests

from sedo import check as chk
from sedo import config as sc
from sedo import iit_client
from sedo import telegram_report as tr
from sedo.client import IITAgentAdapter, SEDOClient, _origin, _safe_doc_id
from sedo.iit_client import IITClient, IITRPCError, _as_port, verify_agent
from sedo.opensc_signer import OpenSCSigner, parse_sign_mechanisms

PIN = "Zx81#pin"
SEDO = "https://sedo.mod.gov.ua"


def _client():
    with patch("sedo.client.SEDOClient._pick_backend", return_value=MagicMock()):
        client = SEDOClient(sedo_url=SEDO)
    client.session = MagicMock()
    return client


# ─── the harnesses themselves ───────────────────────────────

FUZZ = Path(__file__).resolve().parent.parent / "fuzz"


class TestFuzzDirectory:
    """fuzz/ is run by hand, not in CI: at least keep the files, the runner and the README in step."""

    # Each harness in its own directory: fuzz/<name>/fz_<name>.py; fuzz/shared/ is common.
    HARNESSES = sorted(p.parent.name for p in FUZZ.glob("*/fz_*.py"))
    # The one use of __file__ a harness may have: finding fuzz/shared/.
    SHARED = 'sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))'

    def test_one_directory_per_harness(self):
        assert self.HARNESSES
        for path in FUZZ.glob("*/fz_*.py"):
            assert path.name == f"fz_{path.parent.name}.py", path
        assert not list(FUZZ.glob("fz_*.py")), "a harness left in fuzz/ itself"
        assert sorted(p.name for p in (FUZZ / "shared").glob("*.py")) == ["common.py", "strategies.py"]
        assert len(list(FUZZ.glob("*/fz_*.py"))) == len(self.HARNESSES)

    def test_every_harness_compiles(self):
        for path in sorted(FUZZ.rglob("*.py")):
            compile(path.read_text(encoding="utf-8"), str(path), "exec")

    def test_the_runner_and_the_readme_list_them_all(self):
        import ast
        tree = ast.parse((FUZZ / "run.py").read_text(encoding="utf-8"))
        listed = next(ast.literal_eval(node.value) for node in ast.walk(tree)
                      if isinstance(node, ast.Assign) and node.targets[0].id == "HARNESSES")
        assert sorted(listed) == self.HARNESSES
        readme = (FUZZ / "README.md").read_text(encoding="utf-8")
        assert all(f"`{name}/fz_{name}.py`" in readme for name in self.HARNESSES)

    def test_nothing_is_written_next_to_the_harnesses(self):
        # Reproducers go to $FUZZ_OUT / a temp dir (common.save); a PE or a .saz
        # left in the tree could end up in a commit.
        for path in sorted(FUZZ.glob("*/fz_*.py")):
            text = path.read_text(encoding="utf-8")
            assert text.count(self.SHARED) == 1, path.name
            assert "__file__" not in text.replace(self.SHARED, ""), path.name
            assert "tempfile.tempdir" not in text, path.name          # common.py owns the private temp dir


# ─── sedo/client.py ─────────────────────────────────────────

class TestDocumentIds:
    @pytest.mark.parametrize("doc_id", ["a\n", "doc-42\n", "\n"])
    def test_a_trailing_newline_is_not_a_safe_id(self, doc_id):
        # "^…$" matches before a trailing newline: the file was "a\n.zip".
        with pytest.raises(ValueError, match="Unsafe"):
            _safe_doc_id(doc_id)

    def test_a_numeric_id_is_downloaded_under_its_digits(self, tmp_path):
        client = _client()
        client.session.get.return_value = MagicMock(content=b"PK\x03\x04zip")
        path = client.download_document(98765432, tmp_path)
        assert path == tmp_path / "98765432.zip" and path.read_bytes() == b"PK\x03\x04zip"
        assert client.session.get.call_args.args[0] == f"{SEDO}/api/documents/98765432/export"

    @pytest.mark.parametrize("doc_id", [True, -5, 1.5, None, ["1"]])
    def test_other_non_strings_are_still_refused(self, doc_id, tmp_path):
        client = _client()
        with pytest.raises(ValueError, match="Unsafe"):
            client.download_document(doc_id, tmp_path)
        client.session.get.assert_not_called()


class TestNextLinkParsers:
    """urllib and requests must agree on where `next` points; they do not always."""

    def _first_page(self, nxt):
        client = _client()
        page = MagicMock()
        page.json.return_value = {"documents": [{"id": "a"}], "next": nxt}
        client.session.get.side_effect = [page]
        return client

    @pytest.mark.parametrize("nxt", [
        "https://evil.example\\@sedo.mod.gov.ua/api/documents/inbox?page=2",
        "//127.0.0.1\\@sedo.mod.gov.ua:",
        "https://sedo.mod.gov.ua.\\@SEDO.MOD.GOV.UA/",
    ])
    def test_a_backslash_does_not_move_the_host(self, nxt):
        # urlsplit reads the host after "@"; requests connects to the one before "\".
        assert urlsplit(requests.Request("GET", nxt if nxt[0] != "/" else "https:" + nxt)
                        .prepare().url).hostname != "sedo.mod.gov.ua"
        client = self._first_page(nxt)
        with pytest.raises(ValueError, match="not following it"):
            client.fetch_inbox()
        assert client.session.get.call_count == 1

    @pytest.mark.parametrize("nxt", [
        "https://user@sedo.mod.gov.ua/api/documents/inbox?page=2",
        "https://user:secret@sedo.mod.gov.ua/api/documents/inbox?page=2",
    ])
    def test_credentials_in_the_link_are_refused(self, nxt):
        client = self._first_page(nxt)
        with pytest.raises(ValueError, match="not following it"):
            client.fetch_inbox()
        assert client.session.get.call_count == 1

    @pytest.mark.parametrize("nxt", [
        "/api/documents/inbox?page=2", "?page=2", "inbox?cursor=%D1%84",
        "https://sedo.mod.gov.ua/api/documents/inbox?page=2", "https://SEDO.MOD.GOV.UA:443/x?page=é",
    ])
    def test_what_is_followed_goes_to_sedo_for_requests_too(self, nxt):
        client = _client()
        target = client._inbox_next_url(f"{SEDO}/api/documents/inbox", nxt)
        assert _origin(requests.Request("GET", target).prepare().url) == _origin(SEDO)


class TestAgentAdapterReplies:
    """IITAgentAdapter.login when the agent answers with the wrong JSON type."""

    @pytest.mark.parametrize("devices", [{"0": {"devIndex": 0}}, 5, True, "almaz"])
    def test_devices_that_are_not_a_list(self, devices):
        agent = MagicMock()
        agent.enum_key_media_devices.return_value = devices
        with pytest.raises(RuntimeError, match="EnumKeyMediaDevices"):
            IITAgentAdapter(agent).login(PIN)
        agent.read_private_key.assert_not_called()         # the PIN did not leave

    @pytest.mark.parametrize("certs", [{"0": {}}, 5, True, "cert"])
    def test_certificates_that_are_not_a_list(self, certs):
        agent = MagicMock()
        agent.enum_key_media_devices.return_value = [{"devIndex": 0}]
        agent.enum_own_certificates.return_value = certs
        with pytest.raises(RuntimeError, match="EnumOwnCertificates"):
            IITAgentAdapter(agent).login(PIN)


class TestAgentCertificate:
    @pytest.mark.parametrize("info", [{"data": ""}, {"data": "  "}, {"certificate": ""}])
    def test_an_empty_certificate_is_not_a_login(self, info):
        # bytes.fromhex("") is b"": authorize() then sent a 0-byte certificate.
        agent = MagicMock()
        agent.enum_key_media_devices.return_value = [{"devIndex": 0}]
        agent.enum_own_certificates.return_value = [{}]
        agent.get_own_certificate.return_value = info
        adapter = IITAgentAdapter(agent)
        with pytest.raises(RuntimeError, match="empty"):
            adapter.login(PIN)
        with pytest.raises(RuntimeError, match="Not logged in"):
            adapter.get_certificate()

    def test_hex_and_base64_still_decode(self):
        assert IITAgentAdapter._decode_cert("3003020100") == bytes.fromhex("3003020100")
        assert IITAgentAdapter._decode_cert("MAMCAQA=") == bytes.fromhex("3003020100")


class TestBadPinFileInTheCli:
    def test_exit_2_not_a_traceback(self, tmp_path, monkeypatch, caplog):
        from sedo.client import main
        local = tmp_path / "local.toml"
        local.write_text(f"[keys.login]\nbackend = 'pkcs11'\npin_file = '{(tmp_path / 'no-such').as_posix()}'\n",
                         encoding="utf-8")
        for var in ("SEDO_PIN", "SEDO_PIN_LOGIN", "SEDO_MODULE", "SEDO_CONFIG"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["sedo-client", "--config", str(local), "--fetch"])
        with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 2 and "pin_file" in caplog.text


# ─── sedo/iit_client.py ─────────────────────────────────────

def _agent(*bodies, status=200):
    """IITClient whose session answers each call with the next JSON body."""
    with patch("sedo.iit_client.requests.Session") as session_cls:
        session = session_cls.return_value
        replies = []
        for body in bodies:
            r = MagicMock(status_code=status, text=json.dumps(body))
            r.json.return_value = body
            replies.append(r)
        session.post.side_effect = replies
        return IITClient()


class TestAgentErrorCode:
    INF = json.loads("1e999")                      # what Python's json makes of it: inf

    def test_an_infinite_code_is_still_an_rpc_error(self):
        client = _agent({"error": {"code": self.INF, "message": "boom"}})
        with pytest.raises(IITRPCError) as e:
            client.call("GetVersion")
        assert e.value.code == -1

    def test_sign_data_still_falls_back_to_the_old_method_name(self):
        client = _agent({"error": {"code": self.INF, "message": "Requested method not found"}},
                        {"result": "3003020100"})
        assert client.sign_data(b"x") == bytes.fromhex("3003020100")

    def test_registry_port(self):
        assert _as_port(float("inf")) is None and _as_port(float("nan")) is None


class TestVerifyAgentNesting:
    def test_json_nested_too_deep_is_not_the_agent(self):
        reply = MagicMock(status_code=200)
        reply.json.side_effect = RecursionError("maximum recursion depth exceeded")
        with patch("sedo.iit_client.requests.post", return_value=reply):
            assert verify_agent("127.0.0.1", 8080) is False


class TestAgentThatQuotesTheRequest:
    """The PIN goes out in params; whatever comes back must not carry it into logs or errors."""

    @pytest.mark.parametrize("method", sorted(iit_client._REDACTED_METHODS))
    def test_error_message_and_data(self, method):
        client = _agent({"error": {"code": -32602,
                                   "message": f"Invalid method parameters: [{{}}, '{PIN}']",
                                   "data": {"params": [{}, PIN]}}})
        with pytest.raises(IITRPCError) as e:
            client.call(method, [{"devIndex": 0}, PIN])
        assert PIN not in str(e.value) and PIN not in repr(e.value.args)
        assert e.value.data is None
        assert "Invalid method parameters" in str(e.value) and e.value.code == -32602

    def test_error_given_as_a_bare_string(self):
        client = _agent({"error": f"bad password {PIN}"})
        with pytest.raises(IITRPCError) as e:
            client.read_private_key({"devIndex": 0}, PIN)
        assert PIN not in str(e.value) and "bad password" in str(e.value)

    def test_result_is_not_logged(self, caplog):
        client = _agent({"result": f"key read with {PIN}"})
        with caplog.at_level(logging.DEBUG, logger="sedo.iit_client"):
            client.read_private_key({"devIndex": 0}, PIN)
        assert PIN not in caplog.text and "[***]" in caplog.text

    def test_other_methods_keep_their_message_and_log(self, caplog):
        client = _agent({"error": {"code": -32602, "message": "Invalid index 7", "data": [7]}},
                        {"result": "1.3.1"})
        with pytest.raises(IITRPCError, match="Invalid index 7") as e:
            client.get_own_certificate(7)
        assert e.value.data == [7]
        with caplog.at_level(logging.DEBUG, logger="sedo.iit_client"):
            assert client.get_version() == "1.3.1"
        assert "1.3.1" in caplog.text


# ─── sedo/opensc_signer.py ──────────────────────────────────

class TestPkcs11ToolOutput:
    def test_a_mechanism_id_is_32_bits(self):
        lines = ["mechtype-0x" + "F" * 40 + ", sign", "mechtype-0x80420031, keySize={163,509}, sign, verify"]
        assert parse_sign_mechanisms(lines) == [0x80420031]

    def _signer(self, tmp_path):
        tool, module = tmp_path / "pkcs11-tool", tmp_path / "PKCS11.dll"
        tool.write_bytes(b"fake")
        module.write_bytes(b"fake")
        signer = OpenSCSigner(module_path=str(module), pkcs11_tool=str(tool), cert_id="01")
        signer.login(PIN)
        return signer

    @pytest.mark.parametrize("call,what", [("get_certificate", "empty certificate"),
                                           ("sign", "empty signature")])
    def test_exit_0_without_an_output_file(self, tmp_path, call, what):
        # FileNotFoundError on a temp path said nothing, and is not the
        # RuntimeError authorize() collects from a backend.
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
        signer = self._signer(tmp_path)
        with patch("sedo.opensc_signer.subprocess.run", return_value=done):
            with pytest.raises(RuntimeError, match=what):
                signer.sign(b"data") if call == "sign" else signer.get_certificate()


# ─── sedo/check.py ──────────────────────────────────────────

class TestPeBitnessOfACutFile:
    @pytest.mark.parametrize("tail", [b"PE\0\0", b"PE\0\0\x64", b"PE", b""])
    def test_none_not_struct_error(self, tmp_path, tail):
        head = bytearray(b"MZ" + b"\0" * 0x3E)
        struct.pack_into("<I", head, 0x3C, 0x40)
        f = tmp_path / "cut.dll"
        f.write_bytes(bytes(head) + tail)
        assert chk.pe_bitness(f) is None


# ─── sedo/config.py ─────────────────────────────────────────

GOOD = ('[keys.login]\nbackend = "opensc"\n'
        "module = 'C:\\Program Files (x86)\\Institute of Informational Technologies"
        "\\Користувач ЦСК\\PKCS11_EKeyAlmaz1C.dll'\n"
        'cert_id = "01"\n\n[roles]\nauth = "login"\n')


def _load(tmp_path, local: bytes, base: bytes = None):
    (tmp_path / sc.CONFIG_LOCAL).write_bytes(local)
    if base is not None:
        (tmp_path / sc.CONFIG_BASE).write_bytes(base)
    return sc.load_config(client_dir=tmp_path, env={})


class TestConfigAsEditorsSaveIt:
    def test_utf8_bom_is_read(self, tmp_path):
        # Notepad, PowerShell 5 "Set-Content -Encoding UTF8": tomllib said
        # "Invalid statement (at line 1, column 1)".
        cfg = _load(tmp_path, codecs.BOM_UTF8 + GOOD.replace("\n", "\r\n").encode("utf-8"))
        assert cfg.profile("auth").module.endswith("Користувач ЦСК\\PKCS11_EKeyAlmaz1C.dll")

    @pytest.mark.parametrize("blob,kind", [
        (codecs.BOM_UTF16_LE + GOOD.encode("utf-16-le"), "UTF-16"),     # PowerShell 5 ">" / Out-File
        (GOOD.encode("cp1251"), "not UTF-8"),                           # ANSI Notepad, Cyrillic path
    ])
    def test_another_encoding_is_a_config_error_that_says_so(self, tmp_path, blob, kind):
        with pytest.raises(sc.ConfigError, match=kind) as e:
            _load(tmp_path, blob)
        assert sc.CONFIG_LOCAL in str(e.value) and "UTF-8" in str(e.value)


class TestConfigValues:
    @pytest.mark.parametrize("target", ['["login"]', "{}", "1", "true"])
    @pytest.mark.parametrize("where", ["local", "base"])
    def test_a_role_that_is_not_a_name(self, tmp_path, target, where):
        text = f'[keys.login]\nbackend = "opensc"\n[roles]\nauth = {target}\n'.encode("utf-8")
        with pytest.raises(sc.ConfigError, match=r"\[roles\]\.auth"):
            _load(tmp_path, text) if where == "local" else _load(tmp_path, b"", base=text)

    @pytest.mark.parametrize("line", ['cert_id = "01\\n"', 'mechanism = "0x80420031\\n"'])
    def test_a_trailing_newline_is_not_part_of_an_id(self, tmp_path, line):
        with pytest.raises(sc.ConfigError, match=line.split(" ")[0]):
            _load(tmp_path, f'[keys.login]\nbackend = "opensc"\n{line}\n'.encode("utf-8"))


class TestPinFile:
    """What reaches C_Login is exactly the PIN in the file, or nothing is sent at all."""

    def _resolve(self, tmp_path, content: bytes):
        f = tmp_path / "pin.txt"
        f.write_bytes(content)
        return sc.resolve_profile_pin(sc.KeyProfile(name="login", pin_file=str(f)), None, env={})

    @pytest.mark.parametrize("content", [
        b"1234", b"1234\r\n", b"  1234 \n",
        codecs.BOM_UTF8 + b"1234\r\n",                               # Notepad, PS5 -Encoding UTF8
        codecs.BOM_UTF16_LE + "1234\r\n".encode("utf-16-le"),        # PS5: "1234" > pin.txt
        codecs.BOM_UTF16_BE + "1234\n".encode("utf-16-be"),
    ])
    def test_the_pin_and_nothing_else(self, tmp_path, content):
        assert self._resolve(tmp_path, content) == "1234"

    @pytest.mark.parametrize("content", [
        b"1234\n# the token PIN\n",                                  # a second line
        "1234".encode("utf-16-le"),                                  # UTF-16 without a BOM: NULs
        "1234\u200b\n".encode("utf-8"),                              # zero-width space
        b"12\x0034",
        "пароль".encode("cp1251"),                                   # not UTF-8 at all
    ])
    def test_anything_doubtful_is_refused_before_the_token_sees_it(self, tmp_path, content):
        with patch("getpass.getpass", side_effect=AssertionError("must not fall through to a prompt")):
            with pytest.raises(sc.ConfigError, match=r"\[keys\.login\]\.pin_file") as e:
                self._resolve(tmp_path, content)
        assert "1234" not in str(e.value)
        # Nothing reachable from the error holds the file's bytes (UnicodeDecodeError.object).
        chain, seen = [e.value], []
        while chain:
            exc = chain.pop()
            if exc is not None and exc not in seen:
                seen.append(exc)
                chain += [exc.__cause__, exc.__context__]
        assert not any(hasattr(exc, "object") for exc in seen)


class TestCheckReadsThePinFile:
    """--check finds a PIN file the login would refuse — without a token."""

    def _source(self, tmp_path, monkeypatch, content: bytes):
        for var in ("SEDO_PIN", "SEDO_PIN_LOGIN"):
            monkeypatch.delenv(var, raising=False)
        f = tmp_path / "pin.txt"
        f.write_bytes(content)
        return chk._pin_source(sc.KeyProfile("login", pin_file=str(f)), True)

    @pytest.mark.parametrize("content", [b"1234\nsecond line\n", "1234".encode("utf-16-le"), b"12\x0034"])
    def test_a_file_the_login_would_refuse_is_a_failure(self, tmp_path, monkeypatch, content):
        level, text = self._source(tmp_path, monkeypatch, content)
        assert level == chk.FAIL and "1234" not in text and "pin.txt" in text

    def test_bom_is_fine_and_an_empty_file_is_a_warning(self, tmp_path, monkeypatch):
        assert self._source(tmp_path, monkeypatch, codecs.BOM_UTF8 + b"1234\r\n")[0] == chk.OK
        level, text = self._source(tmp_path, monkeypatch, b"\n")
        assert level == chk.WARN and "порожній" in text


# ─── sedo/telegram_report.py ────────────────────────────────

TOKEN = "1234567890:AAF_zQx-testTOKENtestTOKENtestTOKEN99"


class TestTelegramToken:
    @pytest.mark.parametrize("token", [TOKEN + "\n", TOKEN + " ", "١٢٣٤٥٦:" + "A" * 35])
    def test_send_refuses_what_is_not_exactly_a_token(self, token):
        called = []
        with pytest.raises(tr.ReportError, match="does not look like"):
            tr.send(token, "1", "x", post=lambda *a: called.append(a))
        assert not called

    def test_a_newline_after_the_token_in_vault_yml(self, monkeypatch, capsys):
        # bot_token: | … leaves "\n". The URL then had a control character:
        # http.client.InvalidURL, whose message is the URL — token and all.
        summary = {"date": "2026-11-23", "telegram": {"bot_token": TOKEN + "\n", "chat_id": " 42\n"}}
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(summary)))
        urls = []
        monkeypatch.setattr(tr, "_post_json",
                            lambda url, payload, timeout: (urls.append((url, payload)) or (200, {"ok": True})))
        assert tr.main(["--summary", "-"]) == 0
        assert urls[0][0] == f"{tr.TELEGRAM_API}/bot{TOKEN}/sendMessage" and urls[0][1]["chat_id"] == "42"
        assert TOKEN not in "".join(capsys.readouterr())

    @pytest.mark.parametrize("error", [
        lambda url: http.client.InvalidURL(f"URL can't contain control characters. {url!r}"),
        lambda url: ValueError(f"bad url {url}"),
        lambda url: http.client.RemoteDisconnected(f"closed: {url}"),
    ])
    def test_no_exception_from_the_transport_carries_the_url(self, error):
        def post(url, payload, timeout):
            raise error(url)
        with pytest.raises(tr.ReportError, match="unreachable") as e:
            tr.send(TOKEN, "1", "x", post=post)
        assert TOKEN not in str(e.value)
        assert e.value.__context__ is None and e.value.__cause__ is None


class TestSummaryShape:
    @pytest.mark.parametrize("summary", [
        {"workers": "ws01"}, {"workers": [["ws01"]]}, {"workers": 5},
        {"verify": [1]}, {"verify": {"file": "a.zip"}}, {"verify": ["a.zip"]},
    ])
    def test_a_wrong_shape_is_exit_2_with_the_key_named(self, summary, monkeypatch, capsys):
        with pytest.raises(ValueError, match="must be a list of objects"):
            tr.build_report(summary)
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(summary)))
        assert tr.main(["--summary", "-", "--dry-run"]) == 2
        assert "summary: '" in capsys.readouterr().err

    def test_stdout_that_is_not_text(self):
        assert tr.count_documents(["Документів: 3"]) is None
        assert "без завантаження" in tr.build_report({"workers": [{"host": "ws01", "rc": 0, "stdout": 5}]})


class TestTelegramLength:
    @staticmethod
    def _units(text):
        return len(text.encode("utf-16-le")) // 2

    def test_the_limit_is_in_utf16_units(self):
        # 20 workers × an error full of characters outside the BMP: 2 units each.
        workers = [{"host": f"ws{i:02}", "rc": None, "error": "📄" * 150} for i in range(20)]
        text = tr.build_report({"date": "2026-11-23", "workers": workers})
        assert len(text) <= tr.MAX_LEN // 2 + 100             # cut by units, not by code points
        assert self._units(text) <= tr.MAX_LEN and text.endswith("…")
        text.encode("utf-8")                                  # no half of a surrogate pair left

    @pytest.mark.parametrize("n", [tr.MAX_LEN - 1, tr.MAX_LEN, tr.MAX_LEN + 1])
    def test_plain_text_is_cut_as_before(self, n):
        text = tr._fit("x" * n)
        assert len(text) == min(n, tr.MAX_LEN) and (text.endswith("…") == (n > tr.MAX_LEN))


class TestJsonNestedTooDeep:
    """Python 3.11 raises RecursionError from the JSON decoder; it is not a ValueError."""

    def test_inbox(self):
        client = _client()
        page = MagicMock()
        page.json.side_effect = RecursionError("maximum recursion depth exceeded")
        client.session.get.return_value = page
        with pytest.raises(ValueError, match="nested too deep"):
            client.fetch_inbox()

    def test_agent_reply_stays_an_iit_error(self):
        with patch("sedo.iit_client.requests.Session") as session_cls:
            reply = MagicMock(status_code=200, text="[[[[")
            reply.json.side_effect = RecursionError("maximum recursion depth exceeded")
            session_cls.return_value.post.return_value = reply
            client = IITClient()
        with pytest.raises(IITRPCError, match="non-JSON"):
            client.call("GetVersion")
        client.finalize()                               # teardown swallows IITError only


# ─── config_local.toml as Ansible renders it ────────────────

TEMPLATE = Path(__file__).resolve().parent.parent / "ansible" / "playbooks" / "templates" / "config_local.toml.j2"


class TestConfigTemplate:
    """
    Random sedo_keys rendered by ansible-core 2.18 and 2.21 and read back by
    load_config: a profile named in Cyrillic, with a space or a dot produced a
    file the client refused, and a path with a character outside the BMP an
    invalid \\uXXXX escape.
    """

    def test_names_and_values_are_quoted_utf8_strings(self):
        body = TEMPLATE.read_text(encoding="utf-8").split("#}", 1)[1]
        assert "[keys.{{ name | to_json(ensure_ascii=False) }}]" in body
        assert "{{ field }} = {{ value | to_json(ensure_ascii=False) }}" in body
        assert "{{ role }} = {{ name | to_json(ensure_ascii=False) }}" in body
        assert "| to_json }}" not in body                      # no \\uXXXX form anywhere

    @pytest.mark.parametrize("name", ["login", "вхід", "ключ №1", "my key", "a.b", 'k"q', "k'q", "x]y", "a#b"])
    @pytest.mark.parametrize("module", [
        "C:\\Program Files (x86)\\Institute of Informational Technologies\\Користувач ЦСК\\a.dll",
        "C:\\new\\table\\x.dll", "/opt/it's/a \"b\".so", "C:\\ends-with-backslash\\", "a\tb", "📄.dll",
    ])
    def test_what_the_template_writes_is_toml_the_client_reads_back(self, tmp_path, name, module):
        # The template's own expressions, with json.dumps standing in for to_json.
        quote = lambda v: json.dumps(v, ensure_ascii=False)                    # noqa: E731
        text = (f"[keys.{quote(name)}]\nbackend = {quote('opensc')}\nmodule = {quote(module)}\n"
                f"\n[roles]\nauth = {quote(name)}\n")
        cfg = _load(tmp_path, text.encode("utf-8"))
        assert cfg.profile("auth").name == name and cfg.profile("auth").module == module


class TestOnePinVariablePerProfile:
    """SEDO_PIN_<NAME> keeps only A-Z and 0-9 of the name: different names, one variable."""

    def _cfg(self, tmp_path, a, b, extra=""):
        text = (f'[keys."{a}"]\nbackend = "opensc"\n{extra}\n[keys."{b}"]\nbackend = "pkcs11"\n'
                f'[roles]\nauth = "{a}"\nsign = "{b}"\n')
        return _load(tmp_path, text.encode("utf-8"))

    @pytest.mark.parametrize("a,b,env", [("вхід", "підпис", "SEDO_PIN__"), ("key-1", "key.1", "SEDO_PIN_KEY_1"),
                                         ("Login", "login", "SEDO_PIN_LOGIN")])
    def test_two_keys_would_get_one_pin(self, tmp_path, a, b, env):
        assert sc.KeyProfile(a).default_pin_env == sc.KeyProfile(b).default_pin_env == env
        with pytest.raises(sc.ConfigError, match=r"read their PIN from \$" + env):
            self._cfg(tmp_path, a, b)

    def test_an_explicit_pin_env_settles_it(self, tmp_path):
        cfg = self._cfg(tmp_path, "вхід", "підпис", extra='pin_env = "SEDO_PIN_LOGIN"')
        assert cfg.profile("auth").effective_pin_env != cfg.profile("sign").effective_pin_env

    def test_one_profile_or_an_unused_one_is_fine(self, tmp_path):
        text = '[keys."вхід"]\nbackend = "opensc"\n[keys."підпис"]\nbackend = "pkcs11"\n[roles]\nauth = "вхід"\n'
        cfg = _load(tmp_path, text.encode("utf-8"))
        assert [p.name for p in cfg.distinct_profiles()] == ["вхід"]
