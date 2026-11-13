"""
S2: scripts/fiddler_analyze.py must not echo the token PIN from a capture.
"""

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "fiddler_analyze", ROOT / "scripts" / "fiddler_analyze.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_saz(path: Path, method: str, params) -> Path:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    request = (
        "POST /json-rpc HTTP/1.1\r\n"
        "Host: 127.0.0.1:8081\r\n"
        "Content-Type: application/json\r\n"
        "\r\n" + body
    )
    response = "HTTP/1.1 200 OK\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("raw/1_c.txt", request)
        zf.writestr("raw/1_s.txt", response)
    return path


def test_read_private_key_pin_redacted(tmp_path, capsys):
    saz = _make_saz(tmp_path / "cap.saz", "ReadPrivateKey",
                    [{"devIndex": 0, "typeIndex": 7}, "9876"])
    _load_script().analyze(saz)
    out = capsys.readouterr().out
    assert "9876" not in out
    assert "ReadPrivateKey" in out
    assert "[***]" in out


def test_non_secret_method_params_shown(tmp_path, capsys):
    saz = _make_saz(tmp_path / "cap.saz", "GetOwnCertificate", [7])
    _load_script().analyze(saz)
    out = capsys.readouterr().out
    assert "GetOwnCertificate([7])" in out


def test_redaction_set_matches_iit_client():
    """scripts/ duplicates the set — keep it in sync with iit_client."""
    from sedo import iit_client
    assert _load_script()._REDACTED_METHODS == iit_client._REDACTED_METHODS


# ─── The flow report: structure only, safe to hand over ─────────────────────
#
# A synthetic capture of a plausible SEDO login and inbox walk. Every value a
# real capture would carry that must not leave the machine contains SECRET
# (or is the PIN / a document id / a title): the report must show what the
# requests look like and none of those values.

import base64 as _b64
import gzip as _gzip
import io as _io

PIN = "4321"
DOC_ID = "98765432"
TITLE = "Наказ про відрядження"


def _der(content: bytes) -> bytes:
    """A DER SEQUENCE around content (definite length)."""
    n = len(content)
    if n < 0x80:
        return b"\x30" + bytes([n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x30" + bytes([0x80 | len(size)]) + size + content


CMS = _der(bytes.fromhex("06092a864886f70d010702") + bytes.fromhex("060b2a86240201010101030101")
           + b"SECRET-SIGNATURE-BYTES" * 3)
CERT = _der(b"SECRET-CERT CN=Ivan Petrenko RNOKPP 1234567890" * 4)
CHALLENGE = _b64.b64encode(b"SECRET-CHALLENGE-0123456789").decode()


def _jwt(claims: dict) -> str:
    enc = lambda d: _b64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'RS256', 'typ': 'JWT'})}.{enc(claims)}.SECRETsignaturepart"


def _http(start: str, headers: list, body: bytes = b"") -> bytes:
    head = start + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("utf-8") + b"\r\n" + body


def _chunked(data: bytes) -> bytes:
    return b"".join(f"{len(data[i:i + 7]):x}\r\n".encode() + data[i:i + 7] + b"\r\n"
                    for i in range(0, len(data), 7)) + b"0\r\n\r\n"


def _zip_bytes() -> bytes:
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{TITLE} SECRET-NAME.pdf", b"%PDF-1.7 SECRET-DOC-CONTENT")
        zf.writestr(f"{TITLE} SECRET-NAME.pdf.p7s", CMS)
    return buf.getvalue()


def _flow_saz(path: Path) -> Path:
    S = "https://sedo.mod.gov.ua"
    jwt = _jwt({"sub": "SECRET-SUB", "name": "Ivan Petrenko", "exp": 1893456000})
    inbox = json.dumps({"documents": [{"id": DOC_ID, "title": TITLE, "date": "2026-11-13",
                                       "status": "new", "author": {"name": "SECRET-AUTHOR"}}],
                        "next": f"/api/documents/inbox?page=2&cursor=SECRET-CURSOR"},
                       ensure_ascii=False).encode("utf-8")
    sessions = [
        (_http("CONNECT sedo.mod.gov.ua:443 HTTP/1.1", [("Host", "sedo.mod.gov.ua:443")]),
         _http("HTTP/1.1 200 Connection Established", [])),
        (_http(f"GET {S}/ HTTP/1.1", [("Host", "sedo.mod.gov.ua")]),
         _http("HTTP/1.1 200 OK", [("Content-Type", "text/html; charset=utf-8"),
                                   ("Set-Cookie", "SESSION=SECRET-SESSION-1; Path=/; HttpOnly; Secure; SameSite=Lax")],
               ('<html><script src="/static/euscp.js"></script><form method="post" '
                f'action="/auth/kep?ticket=SECRET-TICKET"><input type="hidden" name="nonce" '
                'value="SECRET-NONCE"><input name="login"></form></html>').encode())),
        (_http(f"GET {S}/static/app.SECRET1a2b.js HTTP/1.1", [("Host", "sedo.mod.gov.ua")]),
         _http("HTTP/1.1 200 OK", [("Content-Type", "application/javascript")], b"var SECRET=1")),
        (_http(f"GET {S}/auth/login HTTP/1.1", [("Host", "sedo.mod.gov.ua"),
                                                ("Cookie", "SESSION=SECRET-SESSION-1; lang=uk")]),
         _http("HTTP/1.1 302 Found", [("Location",
               "https://id.gov.ua/?response_type=code&client_id=SECRET-CLIENT&state=SECRET-STATE"
               "&redirect_uri=https%3A%2F%2Fsedo.mod.gov.ua%2Fauth%2Fcallback")])),
        (_http(f"POST {S}/api/auth/kep/init HTTP/1.1", [("Host", "sedo.mod.gov.ua")]),
         _http("HTTP/1.1 200 OK", [("Content-Type", "application/json")],
               json.dumps({"challenge": CHALLENGE, "session_id": "0f8fad5b-d9cb-469f-a165-70867728950e"}).encode())),
        (_http("POST /json-rpc HTTP/1.1", [("Host", "127.0.0.1:8081"), ("Content-Type", "application/json")],
               json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ReadPrivateKey",
                           "params": [{"devIndex": 0, "typeIndex": 7}, PIN]}).encode()),
         _http("HTTP/1.1 200 OK", [], b'{"jsonrpc":"2.0","id":1,"result":null}')),
        (_http("POST /json-rpc HTTP/1.1", [("Host", "127.0.0.1:8081")],
               json.dumps({"jsonrpc": "2.0", "id": 2, "method": "SignData",
                           "params": [CHALLENGE, True]}).encode()),
         _http("HTTP/1.1 200 OK", [], json.dumps({"jsonrpc": "2.0", "id": 2,
                                                   "result": _b64.b64encode(CMS).decode()}).encode())),
        (_http(f"POST {S}/api/auth/kep/verify HTTP/1.1",
               [("Host", "sedo.mod.gov.ua"), ("Content-Type", "application/json"),
                ("Cookie", "SESSION=SECRET-SESSION-1"), ("X-XSRF-TOKEN", "SECRET-XSRF")],
               json.dumps({"signature": _b64.b64encode(CMS).decode(),
                           "certificate": CERT.hex(), "session_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
                           "algorithm": "DSTU4145"}).encode()),
         _http("HTTP/1.1 200 OK", [("Content-Type", "application/json"),
                                   ("Set-Cookie", "AUTH=SECRET-AUTH; Path=/api; HttpOnly")],
               json.dumps({"status": "ok", "token": jwt}).encode())),
        (_http(f"GET https://id.gov.ua/callback?code=SECRET-CODE&state=SECRET-STATE HTTP/1.1",
               [("Host", "id.gov.ua")]),
         _http("HTTP/1.1 302 Found", [("Location", f"{S}/auth/callback?code=SECRET-CODE#access_token=SECRET-AT")])),
        (_http(f"GET {S}/api/documents/inbox?since=2026-11-13 HTTP/1.1",
               [("Host", "sedo.mod.gov.ua"), ("Authorization", f"Bearer {jwt}")]),
         _http("HTTP/1.1 200 OK", [("Content-Type", "application/json; charset=utf-8"),
                                   ("Content-Encoding", "gzip"), ("Transfer-Encoding", "chunked")],
               _chunked(_gzip.compress(inbox)))),
        (_http(f"GET {S}/api/documents/{DOC_ID}/export HTTP/1.1", [("Host", "sedo.mod.gov.ua")]),
         _http("HTTP/1.1 200 OK", [("Content-Type", "application/zip"),
                                   ("Content-Disposition", f'attachment; filename="{DOC_ID} SECRET-NAME.zip"')],
               _zip_bytes())),
    ]
    with zipfile.ZipFile(path, "w") as zf:
        for n, (req, resp) in enumerate(sessions, 1):
            zf.writestr(f"raw/{n:02d}_c.txt", req)
            zf.writestr(f"raw/{n:02d}_s.txt", resp)
    return path


@pytest.fixture
def report(tmp_path, capsys):
    _load_script().analyze(_flow_saz(tmp_path / "flow.saz"))
    return capsys.readouterr().out


class TestFlowReport:
    def test_no_value_from_the_capture_leaks(self, report):
        for secret in ("SECRET", PIN, DOC_ID, TITLE, "Ivan", "Petrenko", "1234567890"):
            assert secret not in report, secret

    def test_requests_in_order_with_masked_paths(self, report):
        flow = report.split("=== Хід:", 1)[1]
        order = ["GET https://sedo.mod.gov.ua/\n", "GET https://sedo.mod.gov.ua/auth/login",
                 "POST https://sedo.mod.gov.ua/api/auth/kep/verify",
                 "GET https://id.gov.ua/callback?code=str(11)&state=str(12)",
                 "GET https://sedo.mod.gov.ua/api/documents/inbox?since=date",
                 "GET https://sedo.mod.gov.ua/api/documents/{id}/export"]
        positions = [flow.index(o) for o in order]
        assert positions == sorted(positions)
        assert "CONNECT" not in flow and "app." not in flow
        assert "пропущено статику .js/.css/зображення: 1" in flow

    def test_cookies_by_name_with_attributes(self, report):
        assert "< Set-Cookie: SESSION (Path=/; HttpOnly; Secure; SameSite=Lax)" in report
        assert "< Set-Cookie: AUTH (Path=/api; HttpOnly)" in report
        assert "> Cookie: SESSION, lang" in report
        assert "> X-XSRF-TOKEN: str(11)" in report

    def test_redirects_keep_parameter_names(self, report):
        assert ("< Location: https://id.gov.ua/?response_type=\"code\"&client_id=str(13)"
                "&state=str(12)&redirect_uri=url(https://sedo.mod.gov.ua/auth/callback)") in report
        assert "#access_token=str(9)" in report

    def test_json_bodies_show_fields_types_and_signature_format(self, report):
        verify = report.split("POST https://sedo.mod.gov.ua/api/auth/kep/verify", 1)[1]
        assert "signature: base64(" in verify and "der cms-signed-data dstu4145)" in verify
        assert "certificate: hex(" in verify and "session_id: uuid" in verify
        assert 'algorithm: "DSTU4145"' in verify
        assert '< JSON {status: "ok", token: jwt(alg=RS256; claims: sub, name, exp)}' in verify

    def test_gzip_chunked_inbox_and_pagination_shape(self, report):
        assert ("< JSON {documents: [1 × {id: digits(8), title: str(21), date: date, "
                'status: "new", author: {name: str(13)}}], '
                "next: path(/api/documents/inbox?page=2&cursor=str(13))}") in report

    def test_export_zip_by_extension_only(self, report):
        assert "< Content-Disposition: attachment; filename=*.zip" in report
        assert "< zip, " in report and "2 entries (.p7s ×1, .pdf ×1)" in report

    def test_html_page_forms_inputs_and_signing_script(self, report):
        assert ("< html, " in report and "form POST /auth/kep?ticket=str(13)" in report
                and "inputs: nonce(hidden), login(text)" in report
                and "signing scripts: euscp.js" in report)

    def test_authorization_scheme_and_token_shape(self, report):
        assert "> Authorization: Bearer jwt(alg=RS256; claims: sub, name, exp)" in report

    def test_links_show_what_is_signed_and_where_it_goes(self, report):
        # The core of the flow, with no value printed: the agent signs SEDO's
        # challenge, SEDO gets the agent's result, the login token is reused.
        flow = report.split("=== Хід:", 1)[1]
        assert "[   7] агент SignData([base64(27 bytes), true]) → base64(" in flow
        assert "         params[0] ← [5] challenge" in flow
        assert "       > signature ← [7] SignData result" in flow
        assert "       > session_id ← [5] session_id" in flow
        assert "       > ?state ← [4] Location?state" in flow
        assert "       > Authorization ← [8] token" in flow
        assert "       > path {id} ← [10] documents[0].id" in flow
        assert "Cookie ←" not in flow                 # every request would link to Set-Cookie

    def test_agent_calls_show_result_shape(self, report):
        assert "ReadPrivateKey([***]) → null" in report
        assert "SignData([base64(27 bytes), true]) → base64(" in report
        assert report.count("cms-signed-data") >= 2


@pytest.fixture(scope="module")
def fa():
    return _load_script()


class TestShapes:
    @pytest.mark.parametrize("value, expected", [
        ("2026-11-13", "date"), ("2026-11-13T08:00:00Z", "datetime"),
        ("0f8fad5b-d9cb-469f-a165-70867728950e", "uuid"), ("1234567890", "digits(10)"),
        ("Іван Петренко", "str(13)"), ("", '""'),
        ("https://sedo.mod.gov.ua/a/12345/b?x=1", "url(https://sedo.mod.gov.ua/a/{id}/b?x=1)"),
        ("00112233445566778899aabbccddeeff", "hex(16 bytes)"),
    ])
    def test_str_shape(self, fa, value, expected):
        assert fa.str_shape(value) == expected

    def test_big_numbers_and_id_keys_are_masked(self, fa):
        assert fa.shape({"page": 2, "total": 123456, "12345678": {"ok": True}}) == \
            "{page: 2, total: int, <id>: {ok: true}}"

    def test_technical_keys_only_and_never_ids_or_emails(self, fa):
        assert fa.shape({"status": "signed", "title": "signed"}) == '{status: "signed", title: str(6)}'
        assert fa.shape({"status": "12345678"}) == "{status: digits(8)}"
        assert fa.shape({"type": "a@b.ua"}) == "{type: str(6)}"

    def test_path_segments(self, fa):
        assert fa.mask_url("/api/v1/documents/doc-123456/export") == "/api/v1/documents/{id}/export"
        assert fa.mask_url("/api/x/0f8fad5b-d9cb-469f-a165-70867728950e") == "/api/x/{uuid}"


def test_output_file_is_utf8(tmp_path):
    out = tmp_path / "report.txt"
    assert _load_script().main([str(_flow_saz(tmp_path / "f.saz")), "--output", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "Хід: СЕДО, id.gov.ua і агент ІІТ" in text and "SECRET" not in text


def test_malformed_urls_do_not_stop_the_report(tmp_path, fa, capsys):
    # urlsplit raises on these; one bad header in a real capture killed the run.
    assert fa.mask_url("http://[::1") == "invalid-url(11)"
    assert fa.mask_url("https://h:abc/x") == "invalid-url(15)"
    saz = tmp_path / "bad.saz"
    with zipfile.ZipFile(saz, "w") as zf:
        zf.writestr("raw/1_c.txt", "GET http://[::1/x HTTP/1.1\r\nHost: sedo.mod.gov.ua\r\n"
                                   "Referer: http://[::1\r\n\r\n")
        zf.writestr("raw/1_s.txt", "HTTP/1.1 302 Found\r\nLocation: http://[::1/x?code=SECRET\r\n\r\n")
    fa.analyze(saz)
    out = capsys.readouterr().out
    assert "invalid-url(" in out and "SECRET" not in out
