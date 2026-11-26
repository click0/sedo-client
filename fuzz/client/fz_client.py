"""Fuzz sedo/client.py against a SEDO double that answers anything."""
import contextlib
import io
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
from common import N, PIN, exc_chain_text, finding, main, response, tb_key, trap_logs  # noqa: E402
from strategies import JSON, SET, dumps, texts  # noqa: E402
from hypothesis import given, settings, strategies as st  # noqa: E402

import sedo.client as sc  # noqa: E402

SEDO = "https://sedo.mod.gov.ua"
SAFE = re.compile(r"[A-Za-z0-9._-]{1,128}")

# ── document ids ──────────────────────────────────────────────────────────────
ids = st.one_of(
    texts, st.integers(), st.none(), st.booleans(), st.floats(), st.lists(st.integers(), max_size=2),
    st.text(alphabet="abcXYZ019._-\n\r\t /\\:\x00", max_size=10),
    st.sampled_from(["a\n", "a\r", "abc.", "con", "COM1.txt", "LPT9", "nul.zip", "a..b", ".", "..",
                     "-", "a" * 128, "a" * 129, "CONIN$", "aux.", "~", "a b", "1", "0"]),
)


@settings(**SET)
@given(ids)
def fuzz_safe_doc_id(doc_id):
    try:
        out = sc._safe_doc_id(doc_id)
    except ValueError:
        return
    except Exception as e:
        finding("_safe_doc_id: " + tb_key(e), doc_id, e)
        return
    if not isinstance(out, str) or not SAFE.fullmatch(out):
        finding("_safe_doc_id accepts an id outside [A-Za-z0-9._-]{1,128}", doc_id, repr(out))
    name = f"{out}.zip"
    if Path("/out", name).resolve().parent != Path("/out"):
        finding("_safe_doc_id: file name escapes the output dir", doc_id, name)


# ── next links ────────────────────────────────────────────────────────────────
hosts = st.sampled_from(["sedo.mod.gov.ua", "SEDO.MOD.GOV.UA", "evil.example", "sedo.mod.gov.ua.evil.example",
                         "127.0.0.1", "[::1]", "[::1", "sedo.mod.gov.ua.", "sedo.mod.gov.ua:443",
                         "sedo.mod.gov.ua:0", "sedo.mod.gov.ua:444", "sedo.mod.gov.ua:abc",
                         "sedo.mod.gov.ua:", "evil.example:443", "", "sedo。mod.gov.ua", "ѕedo.mod.gov.ua"])
seps = st.sampled_from(["@", "\\@", "#@", "?@", "/@", "\\", "%40", "%5c@", " @", "\t", "\n", ":@", ";@", "%2f@"])
schemes = st.sampled_from(["https://", "http://", "HTTPS://", "//", "https:", "https:/", "https:\\\\", "\\\\",
                           "/\\", "ftp://", "javascript:", "file://", "", " https://", "\thttps://", "ht\ntps://"])
paths = st.sampled_from(["", "/", "/api/documents/inbox?page=2", "?page=2", "page2", "../x", "/..//evil.example/",
                         "#frag", "/%2e%2e/", "/a\\b", "//", "/\n", "/ ", "/x?y=\x00", "/é"])


@st.composite
def links(draw):
    kind = draw(st.integers(0, 5))
    if kind == 0:
        return draw(paths)
    if kind == 1:
        return draw(schemes) + draw(hosts) + draw(paths)
    if kind == 2:
        return draw(schemes) + draw(hosts) + draw(seps) + draw(hosts) + draw(paths)
    if kind == 3:
        return draw(schemes) + draw(hosts) + draw(seps) + draw(hosts) + draw(seps) + draw(hosts) + draw(paths)
    if kind == 4:
        return draw(st.text(alphabet="htps:/\\@.#?[]%0a\n\t sedomgvu", max_size=40))
    return draw(texts)


def _effective_origin(url, params=None):
    """Where requests would really connect for this URL (after its own normalisation)."""
    prepared = requests.Request("GET", url, params=params).prepare()
    p = urlsplit(prepared.url)
    return (p.scheme.lower(), p.hostname or "", p.port or {"https": 443, "http": 80}.get(p.scheme.lower()))


class Session:
    """Answers GET/POST from a script of responses; records every URL asked."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
        self.headers = {}

    def _next(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if not self.replies:
            return response(404, b"")
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    def get(self, url, **kw):
        return self._next("GET", url, **kw)

    def post(self, url, **kw):
        return self._next("POST", url, **kw)

    def close(self):
        pass


docs = st.one_of(JSON, st.fixed_dictionaries({"id": ids}, optional={"title": JSON}))
pages = st.one_of(
    JSON,
    st.fixed_dictionaries({}, optional={"documents": st.one_of(JSON, st.lists(docs, max_size=4)),
                                        "next": st.one_of(JSON, links())}),
)
bodies = st.one_of(pages.map(dumps), st.binary(max_size=40),
                   st.sampled_from([b"", b"<html>", b"[" * 3000, b'{"documents":[],"next":1e999}',
                                    b"\xef\xbb\xbf{}", b"\xff\xfe{\x00}\x00", b'{"documents": NaN}']))
statuses = st.sampled_from([200, 200, 200, 200, 201, 204, 301, 302, 401, 403, 404, 500])
ctypes = st.sampled_from(["application/json", "application/json; charset=utf-8", "text/html",
                          "application/json; charset=utf-16", "application/zip", None, "", "text/plain; charset=cp1251"])
replies = st.builds(lambda s, b, c: response(s, b, c), statuses, bodies, ctypes)

ALLOWED = (ValueError, requests.RequestException)


def _client(reply_list):
    c = sc.SEDOClient.__new__(sc.SEDOClient)
    c.sedo_url = SEDO
    c.session = Session(reply_list)
    c.signers, c.profiles, c.config = {}, {}, None
    return c


@settings(**SET)
@given(st.lists(replies, min_size=1, max_size=4), st.one_of(st.none(), texts))
def fuzz_fetch_inbox(reply_list, since):
    c = _client(reply_list)
    try:
        out = c.fetch_inbox(since=since)
    except ALLOWED:
        out = None
    except RecursionError as e:
        finding("fetch_inbox: RecursionError on deeply nested JSON", "[[[[…", e)
        out = None
    except Exception as e:
        finding("fetch_inbox: " + tb_key(e), [r.content for r in reply_list], e)
        out = None
    if out is not None and not isinstance(out, list):
        finding("fetch_inbox returns a non-list", out)
    want = sc._origin(SEDO)
    for _m, url, kw in c.session.calls:
        try:
            got = _effective_origin(url, kw.get("params"))
        except (requests.RequestException, ValueError, UnicodeError):
            continue                              # requests itself would refuse to send
        if got != want:
            finding("fetch_inbox follows 'next' to another origin (URL parser differential)",
                    url, f"requests connects to {got}, SEDO is {want}")


@settings(**SET)
@given(links())
def fuzz_next_url(nxt):
    c = _client([])
    try:
        target = c._inbox_next_url(SEDO + "/api/documents/inbox", nxt)
    except ValueError:
        return
    except Exception as e:
        finding("_inbox_next_url: " + tb_key(e), nxt, e)
        return
    try:
        got = _effective_origin(target)
    except (requests.RequestException, ValueError, UnicodeError):
        return
    if got != sc._origin(SEDO):
        finding("_inbox_next_url accepts a link requests sends elsewhere", nxt,
                f"target {target!r} → requests connects to {got}")


@settings(**SET)
@given(st.binary(max_size=60), ctypes, st.booleans())
def fuzz_document_body(body, ctype, redirected):
    r = response(200, body, ctype, history=[response(302)] if redirected else [])
    try:
        out = sc._document_body("doc1", r)
    except ValueError:
        return
    except Exception as e:
        finding("_document_body: " + tb_key(e), (body, ctype), e)
        return
    if out != body or not out:
        finding("_document_body changes or accepts an empty body", (body, ctype))
    if re.match(rb"\s*<(!doctype html|html)", out[:200], re.I):
        finding("_document_body accepts an HTML page", (body, ctype))


@settings(**SET)
@given(statuses, st.one_of(JSON.map(dumps), st.binary(max_size=30)), ctypes)
def fuzz_verify_accepted(status, body, ctype):
    r = response(status, body, ctype)
    try:
        out = sc._verify_accepted(r)
    except RecursionError:
        return
    except Exception as e:
        finding("_verify_accepted: " + tb_key(e), (status, body, ctype), e)
        return
    if out is True and not 200 <= status < 300:
        finding("_verify_accepted accepts a non-2xx", (status, body))


class Signer:
    signature_format = "raw"

    def __init__(self):
        self.signed = []

    def login(self, pin):
        assert pin == PIN

    def get_certificate(self):
        return b"\x30\x03cer"

    def sign(self, data):
        if not isinstance(data, bytes):
            raise TypeError(f"sign() got {type(data).__name__}")
        self.signed.append(data)
        return b"\x01\x02sig"

    def logout(self):
        pass


kep = st.one_of(JSON, st.fixed_dictionaries({}, optional={
    "challenge": st.one_of(JSON, st.text(max_size=20), st.sampled_from(["QUJD", "====", "    ", "\ud800", "é"])),
    "nonce": JSON, "data": JSON, "session_id": JSON, "id": JSON}))
kep_replies = st.builds(lambda s, b, c: response(s, b, c), statuses,
                        st.one_of(kep.map(dumps), st.binary(max_size=20)), ctypes)


@settings(**SET)
@given(st.lists(kep_replies, max_size=7))
def fuzz_authorize(reply_list):
    c = _client(reply_list)
    signer = Signer()
    c.signers = {"auth": signer, "sign": signer}
    c.profiles = {"auth": None, "sign": None}
    c.signer = signer
    trap = trap_logs()
    try:
        c.authorize(PIN)
    except RuntimeError as e:
        if PIN in exc_chain_text(e):
            finding("authorize: PIN in the exception", str(e))
    except Exception as e:
        finding("authorize: " + tb_key(e), [r.content for r in reply_list], e)
    if PIN in trap.text():
        finding("authorize: PIN in the log", trap.text()[:300])
    if "LOGGING ERROR" in trap.text():
        finding("authorize: broken log call", trap.text()[:300])
    for _m, url, kw in c.session.calls:
        if PIN in repr((url, kw)):
            finding("authorize: PIN in an HTTP request", (url, kw))
    if b"" in signer.signed:
        finding("authorize signs an EMPTY challenge", [r.content for r in reply_list])


# ── the whole CLI ─────────────────────────────────────────────────────────────
@settings(**{**SET, "max_examples": max(200, N // 4)})
@given(st.lists(replies, max_size=5), st.booleans())
def fuzz_main(reply_list, with_since):
    tmp = tempfile.mkdtemp(prefix="fzmain-")
    out_dir = Path(tmp) / "out"
    cfg_dir = Path(tmp) / "cfg"
    cfg_dir.mkdir()
    signer = Signer()
    # verify + init must succeed for --fetch to be reached: script them first.
    script = [response(302, b"", None),                                 # /auth/login (oidc: not id.gov.ua)
              response(200, b'{"challenge": "QUJD"}'), response(200, b'{"ok": true}')] + list(reply_list)
    session = Session(script)
    argv = ["sedo_client.py", "--backend", "pkcs11", "--fetch", "--output", str(out_dir)]
    if with_since:
        argv += ["--since", "2026-11-23"]
    old = (sys.argv, sc.requests.Session, sc.SEDOClient._pick_backend, sc.load_config)
    sys.argv = argv
    sc.requests.Session = lambda: session
    sc.SEDOClient._pick_backend = lambda self, *a, **k: signer
    sc.load_config = lambda local_path=None: old[3](client_dir=cfg_dir, local_path=local_path, env={})
    os.environ["SEDO_PIN"] = PIN
    stdout, stderr = io.StringIO(), io.StringIO()
    trap = trap_logs()
    code = None
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            sc.main()
        code = 0
    except SystemExit as e:
        code = e.code
    except BaseException as e:
        finding("main(): uncaught " + tb_key(e), [r.content for r in reply_list], e)
    finally:
        sys.argv, sc.requests.Session, sc.SEDOClient._pick_backend, sc.load_config = old
        logging_text = trap.text()
    everything = stdout.getvalue() + stderr.getvalue() + logging_text
    if PIN in everything:
        finding("main(): PIN in output/log", everything[:300])
    if code not in (0, 1, None):
        finding(f"main(): unexpected exit code {code!r}", [r.content for r in reply_list])
    files = [p for p in Path(tmp).rglob("*") if p.is_file()]
    for p in files:
        if p.parent != out_dir or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}\.zip", p.name):
            finding("main(): file written outside <output>/<safe id>.zip", str(p.relative_to(tmp)))
        elif p.read_bytes()[:1] == b"" or p.stat().st_size == 0:
            finding("main(): empty document saved", p.name)
    m = re.search(r"Документів: (\d+)", stdout.getvalue())
    if code == 0 and not m:
        finding("main(): exit 0 without the 'Документів: N' line the playbook greps", stdout.getvalue())
    if code == 0 and m:
        n_ok = stdout.getvalue().count("  ✓ ")
        if n_ok != len(files):
            finding("main(): printed ✓ lines != files on disk", (stdout.getvalue(), [p.name for p in files]))
    # A numeric id is what a JSON API most plausibly sends: note when it kills the run.
    if code == 1 and "Unsafe document id" in logging_text:
        mm = re.search(r"Unsafe document id: (\d+)$", logging_text, re.M)
        if mm:
            finding("main(): a numeric document id aborts the whole run", mm.group(0))
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main("sedo/client.py", fuzz_safe_doc_id, fuzz_next_url, fuzz_fetch_inbox, fuzz_document_body,
         fuzz_verify_accepted, fuzz_authorize, fuzz_main)
