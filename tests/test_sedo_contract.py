"""
Contract tests written ahead of the Fiddler capture.

The spec is README «Поточний стан» (login with the KEP, fetch the inbox,
verify with ua-sign-verify, report) plus FIDDLER-CAPTURE-GUIDE.md, whose
expected JSON shapes EXPECTED below mirrors. Two kinds of test:

* "holds today": behaviour that must stay true whatever the real endpoints
  turn out to be (cookie carried from verify to the inbox, a rejection is
  never a success, an expired session never yields an empty inbox, the CLI
  output the playbooks parse). They run against a real in-process HTTP
  stand-in with the fake signer, in every CI job — no SoftHSM needed.
* xfail(strict=True): the contract for what is not implemented yet. When the
  feature lands the test XPASSes, CI goes red, and the marker is removed —
  from then on the test guards the implementation. Each reason names what is
  missing.

After the capture: update EXPECTED from docs/sedo-flow.md, then clear the
markers one by one.
"""

import base64
import io
import json
import re
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from sedo.client import SEDOClient, _build_parser

ROOT = Path(__file__).resolve().parent.parent

# What FIDDLER-CAPTURE-GUIDE.md expects to see; the stand-in speaks exactly this.
EXPECTED = {
    "init": {"challenge": "<base64>", "session_id": "s1", "algorithm": "DSTU4145-257"},
    "verify_request": ("session_id", "signature", "certificate"),
    "verify_response": {"authenticated": True},
    "cookie": "sedo_session",
    "inbox": {"documents": [{"id": "doc-1", "title": "Наказ № 1", "date": "2026-11-01"},
                            {"id": "doc-2", "title": "Лист", "date": "2026-11-01"}]},
}
CHALLENGE = b"\x01\x02" * 16                      # 32 random bytes in real life
CODE = "c0de"


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


class FakeSigner:
    def __init__(self, name="auth"):
        self.name, self.logged_in, self.signed = name, False, []
        self.cert = b"\x30\x82" + name.encode() + b"\0" * 60

    def login(self, pin):
        self.logged_in = True

    def get_certificate(self):
        return self.cert

    def sign(self, data):
        self.signed.append(data)
        return b"sig:" + self.name.encode() + b":" + data[:8]

    def logout(self):
        self.logged_in = False


class SEDO(ThreadingHTTPServer):
    """
    Local stand-in for sedo.mod.gov.ua. Scenario knobs are attributes so a
    test flips exactly one thing: `scenario` ("direct_kep" | "oidc" | "cms"),
    `init_paths`, `plain_nonce`, `verify_response`, `unauth` ("401" | "302"),
    `pages`, `export`. Every request lands in `requests` for assertions.
    """

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.url = f"http://127.0.0.1:{self.server_address[1]}"
        self.requests: list[dict] = []
        self.scenario = "direct_kep"
        self.init_paths = {"/api/auth/kep/init"}
        self.plain_nonce = False
        self.verify_response = dict(EXPECTED["verify_response"])
        self.cookie = f"{EXPECTED['cookie']}=t0k3n"
        self.unauth = "401"
        self.pages = None                     # [[docs page1], [docs page2]] → paginated
        self.export = ("application/zip", _zip({"doc.pdf": b"%PDF-1.4", "doc.p7s": b"\x30\x82"}))
        self.documents = [dict(d) for d in EXPECTED["inbox"]["documents"]]

    def start(self):
        # shutdown() waits for the next poll; the default 0.5 s made every
        # teardown cost half a second (~10 s of the whole suite).
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.01},
                         daemon=True).start()
        return self

    def paths(self, method=None):
        return [r["path"] for r in self.requests if method in (None, r["method"])]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # ── plumbing ──
    def _send(self, code, body=b"", ctype="application/json", headers=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj, headers=()):
        self._send(code, json.dumps(obj).encode(), headers=headers)

    def _redirect(self, location):
        self._send(302, b"", "text/html", [("Location", location)])

    def _record(self, method):
        parts = urlsplit(self.path)
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        rec = {"method": method, "path": parts.path, "query": parse_qs(parts.query),
               "headers": dict(self.headers), "raw": raw, "json": None}
        if raw and "json" in (self.headers.get("Content-Type") or ""):
            try:
                rec["json"] = json.loads(raw)
            except ValueError:
                pass
        self.server.requests.append(rec)
        return rec

    def _authed(self):
        return self.server.cookie.split("=")[0] + "=" in (self.headers.get("Cookie") or "")

    def _deny(self):
        if self.server.unauth == "302":
            self._redirect(f"{self.server.url}/auth/login")
        else:
            self._json(401, {"error": "unauthorized"})

    # ── routes ──
    def do_GET(self):
        srv: SEDO = self.server
        rec = self._record("GET")
        p = rec["path"]
        if p == "/auth/login":
            if srv.scenario == "oidc":
                # The real IdP is id.gov.ua; the client detects it by that
                # substring, so the local stand-in carries it in the query.
                self._redirect(f"{srv.url}/idp/authorize?client_id=sedo&idp=id.gov.ua&state=st1")
            else:
                self._send(200, b"<html>login</html>", "text/html")
        elif p == "/idp/authorize":
            self._json(200, {"challenge": base64.b64encode(CHALLENGE).decode(), "state": "st1"})
        elif p == "/auth/callback":
            if rec["query"].get("code") == [CODE]:
                self._send(302, b"", "text/html",
                           [("Set-Cookie", srv.cookie + "; HttpOnly; Path=/"), ("Location", f"{srv.url}/home")])
            else:
                self._json(400, {"error": "bad code"})
        elif p == "/home":
            self._send(200, b"<html>home</html>", "text/html")
        elif p == "/api/documents/inbox":
            if not self._authed():
                return self._deny()
            if srv.pages:
                n = int(rec["query"].get("page", ["1"])[0])
                body = {"documents": srv.pages[n - 1]}
                if n < len(srv.pages):
                    body["next"] = f"/api/documents/inbox?page={n + 1}"
                self._json(200, body)
            else:
                self._json(200, {"documents": srv.documents})
        elif (m := re.fullmatch(r"/api/documents/([^/]+)/export", p)):
            if not self._authed():
                return self._deny()
            ctype, body = srv.export
            self._send(200, body, ctype, [("Content-Disposition", f'attachment; filename="{m.group(1)}.zip"')])
        elif (m := re.fullmatch(r"/api/documents/([^/]+)/sign/init", p)):
            if not self._authed():
                return self._deny()
            self._json(200, {"data": base64.b64encode(b"to-sign:" + m.group(1).encode()).decode()})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        srv: SEDO = self.server
        rec = self._record("POST")
        p = rec["path"]
        if p in srv.init_paths:
            challenge = "plain-nonce-not-base64!" if srv.plain_nonce else base64.b64encode(CHALLENGE).decode()
            self._json(200, {"challenge": challenge, "session_id": "s1", "algorithm": "DSTU4145-257"})
        elif p.endswith("/verify") and p.startswith(("/api/auth", "/auth/kep", "/login/kep")):
            body = rec["json"] or {}
            if not all(body.get(k) for k in EXPECTED["verify_request"]) or body["session_id"] != "s1":
                return self._json(400, {"error": "bad verify request"})
            ok = srv.verify_response.get("authenticated") is True
            self._json(200, srv.verify_response,
                       [("Set-Cookie", srv.cookie + "; HttpOnly; Path=/")] if ok else ())
        elif p == "/idp/verify":
            self._redirect(f"{srv.url}/auth/callback?code={CODE}&state=st1")
        elif p == "/api/auth/cms":
            ctype = self.headers.get("Content-Type") or ""
            if "pkcs7" in ctype or (rec["json"] or {}).get("signedData"):
                self._json(200, {"authenticated": True}, [("Set-Cookie", srv.cookie + "; Path=/")])
            else:
                self._json(400, {"error": "expected CMS SignedData"})
        elif re.fullmatch(r"/api/documents/[^/]+/sign/verify", p):
            if not self._authed():
                return self._deny()
            self._json(200, {"ok": bool((rec["json"] or {}).get("signature"))})
        else:
            self._json(404, {"error": "not found"})


@pytest.fixture
def sedo():
    srv = SEDO().start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _client(srv, signer=None, **kw):
    signer = signer or FakeSigner()
    with patch("sedo.client.SEDOClient._pick_backend", return_value=signer):
        c = SEDOClient(sedo_url=srv.url, **kw)
    return c, signer


def XFAIL(reason):
    return pytest.mark.xfail(strict=True, reason=reason)


# ═══ 1. Holds today: the direct-KEP contract against a real HTTP server ═══

class TestDirectKEP:
    def test_authorize_then_fetch_then_download(self, sedo, tmp_path):
        c, signer = _client(sedo)
        with c:
            c.authorize("1234")
            docs = c.fetch_inbox(since="2026-11-01")
            path = c.download_document(docs[0]["id"], tmp_path / "out")

        # signer saw the decoded challenge, exactly once
        assert signer.signed == [CHALLENGE]
        # verify request carries base64 signature + certificate + the init session id
        verify = next(r for r in sedo.requests if r["path"] == "/api/auth/kep/verify")
        assert set(EXPECTED["verify_request"]) <= set(verify["json"])
        assert base64.b64decode(verify["json"]["certificate"]) == signer.cert
        assert base64.b64decode(verify["json"]["signature"]).startswith(b"sig:auth:")
        # the cookie set by verify reaches the inbox and the export
        for p in ("/api/documents/inbox", "/api/documents/doc-1/export"):
            r = next(r for r in sedo.requests if r["path"] == p)
            assert EXPECTED["cookie"] + "=" in r["headers"].get("Cookie", ""), p
        inbox = next(r for r in sedo.requests if r["path"] == "/api/documents/inbox")
        assert inbox["query"] == {"since": ["2026-11-01"]}
        assert [d["id"] for d in docs] == ["doc-1", "doc-2"]
        assert path == tmp_path / "out" / "doc-1.zip"
        assert zipfile.ZipFile(path).namelist() == ["doc.pdf", "doc.p7s"]

    def test_second_candidate_endpoint_is_found(self, sedo):
        """Only /auth/kep/challenge exists: the client must reach it and verify next to it."""
        sedo.init_paths = {"/auth/kep/challenge"}
        c, _ = _client(sedo)
        with c:
            c.authorize("1234")
        assert "/api/auth/kep/init" in sedo.paths("POST")          # tried first, 404
        assert sedo.paths("POST")[-2:] == ["/auth/kep/challenge", "/auth/kep/verify"]

    def test_plain_nonce_is_signed_verbatim(self, sedo):
        sedo.plain_nonce = True
        c, signer = _client(sedo)
        with c:
            c.authorize("1234")
        assert signer.signed == [b"plain-nonce-not-base64!"]

    @pytest.mark.parametrize("verify_response", [
        {"authenticated": False},
        {"error": "signature invalid"},
        {"success": False, "message": "cert not registered"},
    ])
    def test_rejection_is_never_a_success(self, sedo, verify_response):
        sedo.verify_response = verify_response
        c, _ = _client(sedo)
        with c, pytest.raises(RuntimeError, match="All auth flows failed"):
            c.authorize("1234")
        assert not c.session.cookies, "no cookie may survive a rejected verify"
        assert "/api/documents/inbox" not in sedo.paths()

    def test_flows_do_not_leak_the_pin(self, sedo):
        c, _ = _client(sedo)
        with c:
            c.authorize("secret-pin-7777")
        for r in sedo.requests:
            assert b"secret-pin-7777" not in r["raw"]
            assert "secret-pin-7777" not in json.dumps(r["headers"])


class TestSessionExpiry:
    """An expired/missing session must surface as an error, never as "0 documents"."""

    @pytest.mark.parametrize("unauth", ["401", "302"])
    def test_inbox_without_session_raises(self, sedo, unauth):
        sedo.unauth = unauth
        c, _ = _client(sedo)
        with c, pytest.raises((requests.HTTPError, ValueError)):
            c.fetch_inbox()

    def test_download_401_raises_and_writes_nothing(self, sedo, tmp_path):
        c, _ = _client(sedo)
        with c, pytest.raises(requests.HTTPError):
            c.download_document("doc-1", tmp_path / "out")
        assert not list((tmp_path / "out").glob("*")) if (tmp_path / "out").exists() else True

    @pytest.mark.parametrize("export", [
        ("text/html; charset=utf-8", b"<html>session expired, log in</html>"),
        ("application/octet-stream", b"\xef\xbb\xbf\r\n<!DOCTYPE html><title>Login</title>"),
        ("application/zip", b""),
    ], ids=["text/html", "sniffed-html", "empty"])
    def test_download_of_a_non_document_is_rejected(self, sedo, tmp_path, export):
        sedo.export = export
        c, _ = _client(sedo)
        c.session.cookies.set(EXPECTED["cookie"], "t0k3n")
        with c, pytest.raises(ValueError, match="doc-1.*nothing saved"):
            c.download_document("doc-1", tmp_path / "out")
        assert not (tmp_path / "out" / "doc-1.zip").exists()

    def test_expired_session_redirect_to_login_is_rejected(self, sedo, tmp_path):
        """No cookie, the server answers 302 → /auth/login, requests follows it to 200 HTML."""
        sedo.unauth = "302"
        c, _ = _client(sedo)
        with c, pytest.raises(ValueError, match=r"redirected to .*/auth/login"):
            c.download_document("doc-1", tmp_path / "out")
        assert not (tmp_path / "out" / "doc-1.zip").exists()

    def test_non_zip_document_is_saved_with_a_warning(self, sedo, tmp_path, caplog):
        sedo.export = ("application/pdf", b"%PDF-1.4 signed")
        c, _ = _client(sedo)
        c.session.cookies.set(EXPECTED["cookie"], "t0k3n")
        with c, caplog.at_level("WARNING", logger="sedo.client"):
            path = c.download_document("doc-1", tmp_path / "out")
        assert path.read_bytes() == b"%PDF-1.4 signed"
        assert "not a ZIP (Content-Type application/pdf)" in caplog.text

    def test_cli_stops_on_an_html_export(self, sedo, tmp_path, monkeypatch, capsys, caplog):
        """The daily run fails loudly (exit 1) instead of reporting HTML pages as documents."""
        from sedo.client import main
        sedo.export = ("text/html", b"<html>login</html>")
        monkeypatch.setenv("SEDO_PIN", "1234")
        monkeypatch.setattr(sys, "argv", ["sedo-client", "--url", sedo.url, "--fetch",
                                          "--output", str(tmp_path / "dl")])
        with patch("sedo.client.SEDOClient._pick_backend", return_value=FakeSigner()), \
             pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 1
        assert "HTML page instead of the document" in caplog.text
        assert not list((tmp_path / "dl").glob("*.zip"))


# ═══ 2. Contract with the playbooks and the CLI ═══

class TestCLIContract:
    def test_fetch_prints_what_the_playbook_parses(self, sedo, tmp_path, monkeypatch, capsys):
        """`changed_when` in both playbooks greps the stdout: the format is an interface."""
        from sedo.client import main
        monkeypatch.setenv("SEDO_PIN", "1234")
        monkeypatch.setattr(sys, "argv", ["sedo-client", "--url", sedo.url, "--fetch",
                                          "--since", "2026-11-01", "--output", str(tmp_path / "dl")])
        with patch("sedo.client.SEDOClient._pick_backend", return_value=FakeSigner()):
            main()
        out = capsys.readouterr().out
        assert "✓ Авторизація успішна" in out
        assert sorted(p.name for p in (tmp_path / "dl").glob("*.zip")) == ["doc-1.zip", "doc-2.zip"]
        for pb in ("sedo_daily.yml", "sedo_daily_linux.yml"):
            text = (ROOT / "ansible" / "playbooks" / pb).read_text(encoding="utf-8")
            m = re.search(r"search\('([^']+)'\)", text)
            assert m, f"{pb}: no changed_when search()"
            assert re.search(m.group(1), out), f"{pb}: pattern {m.group(1)!r} not in CLI output"

    def test_playbooks_only_pass_flags_the_parser_knows(self):
        known = set(_build_parser()._option_string_actions)
        for pb in ("sedo_daily.yml", "sedo_daily_linux.yml"):
            text = (ROOT / "ansible" / "playbooks" / pb).read_text(encoding="utf-8")
            # The run task itself. Matching from the first "sedo_client.py" hit
            # the header comment, so only its "--pin" was ever checked.
            tasks = [re.sub(r"^\s*#.*$", "", t, flags=re.M)
                     for t in re.split(r"\n(?= +- name: )", text)]
            runs = [t for t in tasks if re.search(r"^ +(argv|cmd):", t, re.M) and "--fetch" in t]
            assert len(runs) == 1, f"{pb}: client invocation not found"
            flags = set(re.findall(r"(--[a-z][a-z-]*)", runs[0]))
            assert {"--fetch", "--since", "--output", "--backend", "--url"} <= flags, f"{pb}: {flags}"
            assert flags <= known, f"{pb}: unknown flags {flags - known}"

    def test_zero_documents_is_not_changed(self, sedo, tmp_path, monkeypatch, capsys):
        from sedo.client import main
        sedo.documents = []
        monkeypatch.setenv("SEDO_PIN", "1234")
        monkeypatch.setattr(sys, "argv", ["sedo-client", "--url", sedo.url, "--fetch",
                                          "--output", str(tmp_path / "dl")])
        with patch("sedo.client.SEDOClient._pick_backend", return_value=FakeSigner()):
            main()
        out = capsys.readouterr().out
        assert "Документів: 0" in out and not re.search(r"Документів: [1-9]", out)


# ═══ 3. Written ahead: what the Fiddler capture has to unlock ═══

class TestOIDCAhead:
    @XFAIL("_flow_oidc detects id.gov.ua and returns False: the OIDC dance "
           "(IdP challenge → signature → callback with code → session cookie) is not implemented")
    def test_oidc_dance_ends_with_a_session(self, sedo):
        sedo.scenario = "oidc"
        sedo.init_paths = set()                        # no direct-KEP endpoint exists
        c, signer = _client(sedo)
        with c:
            c.authorize("1234")
            docs = c.fetch_inbox()
        assert signer.signed == [CHALLENGE]
        assert "/auth/callback" in sedo.paths("GET")
        assert EXPECTED["cookie"] in c.session.cookies
        assert len(docs) == 2


class TestCMSAhead:
    @XFAIL("_flow_cms_post raises NotImplementedError: needs the endpoint and a "
           "CAdES-BES/CMS SignedData builder (the signers return raw r||s only)")
    def test_cms_post_authorizes(self, sedo):
        sedo.init_paths = set()
        c, _ = _client(sedo)
        with c:
            c.authorize("1234")
        cms = next(r for r in sedo.requests if r["path"] == "/api/auth/cms")
        assert "pkcs7" in cms["headers"].get("Content-Type", "") or cms["json"]["signedData"]
        assert EXPECTED["cookie"] in c.session.cookies


class TestInboxAhead:
    @XFAIL("fetch_inbox reads one page: a `next` link in the inbox response is ignored")
    def test_pagination_is_followed(self, sedo):
        sedo.pages = [[{"id": "a"}, {"id": "b"}], [{"id": "c"}]]
        c, _ = _client(sedo)
        c.session.cookies.set(EXPECTED["cookie"], "t0k3n")
        with c:
            docs = c.fetch_inbox()
        assert [d["id"] for d in docs] == ["a", "b", "c"]
        assert sedo.paths("GET").count("/api/documents/inbox") == 2


class TestDocumentSigningAhead:
    """README: the `sign` role works only via --sign-file; signing inside SEDO is not there."""

    @XFAIL("no SEDOClient method signs a document inside SEDO yet (endpoints unknown); "
           "the contract: data from SEDO → signers['sign'] (never the auth key) → posted back")
    def test_sign_in_sedo_uses_the_document_key(self, sedo):
        auth, doc = FakeSigner("auth"), FakeSigner("doc")
        c, _ = _client(sedo, signer=auth)
        c.signers["sign"] = doc
        with c:
            c.authorize("1234")
            c.login("sign", "5678")
            c.sign_in_sedo("doc-1")
        assert doc.signed == [b"to-sign:doc-1"]
        assert auth.signed == [CHALLENGE]                 # the login key signed only the challenge
        posted = next(r for r in sedo.requests if r["path"] == "/api/documents/doc-1/sign/verify")
        assert base64.b64decode(posted["json"]["signature"]).startswith(b"sig:doc:")
