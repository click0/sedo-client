"""Fuzz scripts/fiddler_analyze.py for the one thing it promises: structure only, no values.

Every VALUE in a generated capture (cookie, token, query value, id in a path, JSON string, form
field, file name, HTML text, agent parameter, certificate bytes) carries a unique marker. The
report may show names of things; a marker in it, raw or encoded, is a leak.
"""
import base64
import contextlib
import gzip
import importlib.util
import io
import json
import os
import re
import sys
import zipfile
import zlib
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import N, ROOT, SEED, TMP, finding, main, rnd, save, tb_key  # noqa: E402

# FA_SCRIPT: another copy of the script — an older one, to see that the harness
# still finds in it what it was written to find.
spec = importlib.util.spec_from_file_location(
    "fa", os.environ.get("FA_SCRIPT") or ROOT / "scripts" / "fiddler_analyze.py")
fa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fa)

WORDS = ["Petrenko", "Shevchenko", "Наказ", "відрядження", "Іваненко", "secretword"]


class Secrets:
    """Hands out unique marked values and remembers them with the place they were put."""

    def __init__(self):
        self.items = []                      # (value, where)
        self.n = 0

    def _tag(self):
        self.n += 1
        return f"{rnd.choice('QZXJ')}{rnd.randrange(16 ** 6):06x}{self.n:03d}"

    def opaque(self, where):
        """A session id / code / token: letters and digits."""
        v = "zQ" + self._tag() + rnd.choice(["", "Kx7", "-Ab_9", "f" * rnd.randrange(0, 30)])
        self.items.append((v, where))
        return v

    def digits(self, where):
        v = str(rnd.randrange(10 ** 7, 10 ** 12))
        self.items.append((v, where))
        return v

    def text(self, where):
        """Human text: a name, a title — words with a marked word among them."""
        v = f"{rnd.choice(WORDS)} mk{self._tag()} {rnd.choice(WORDS)}"
        self.items.append((v.split()[1], where))
        return v

    def word(self, where):
        """One alphabetic word (a surname): no digits to give it away."""
        v = "Wq" + "".join(rnd.choice("abcdefghkmnprstuvxyz") for _ in range(rnd.randrange(6, 14)))
        self.items.append((v, where))
        return v

    def free(self, where):
        """Free text that cannot pass for a list of technical words (has a Cyrillic word)."""
        v = f"{rnd.choice(['Наказ', 'відрядження', 'Іваненко'])} mk{self._tag()} {rnd.choice(WORDS)}"
        self.items.append((v.split()[1], where))
        return v

    def by_design(self, where):
        """A NAME the report shows on purpose (host, script file, field name): filled, not tracked."""
        return "zN" + self._tag()

    def any(self, where):
        return rnd.choice([self.opaque, self.opaque, self.digits, self.text, self.word])(where)

    def encoded(self, where):
        """A value in one of the encodings real flows use; the plain marker is what must not show."""
        raw = self.opaque(where)
        kind = rnd.randrange(6)
        if kind == 0:
            return base64.b64encode((raw * rnd.randrange(1, 4)).encode()).decode()
        if kind == 1:
            return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        if kind == 2:
            return (raw * 2).encode().hex()
        if kind == 3:                         # JWT with the marker in a claim
            enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
            return f"{enc({'alg': 'RS256'})}.{enc({'sub': raw, 'name': self.text(where + ' (jwt claim)')})}.{self.opaque(where + ' (jwt sig)')}"
        if kind == 4:                         # DER-looking blob (certificate / CMS) with the marker inside
            body = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" + raw.encode() * 3
            der = b"\x30\x81" + bytes([len(body)]) + body if len(body) < 256 else b"\x30\x82" + len(body).to_bytes(2, "big") + body
            return base64.b64encode(der).decode() if rnd.random() < .5 else der.hex()
        return quote(self.text(where))


S = "https://sedo.mod.gov.ua"
JSON_KEYS = ["id", "title", "name", "author", "token", "code", "state", "nonce", "challenge", "signature",
             "certificate", "session_id", "email", "subject", "documents", "next", "items", "data", "result",
             "user", "fio", "comment", "description", "message", "error_description", "file", "filename", "url",
             "href", "cursor", "page", "total", "access_token", "refresh_token", "id_token", "sign", "value"]
SHOWN = ["status", "type", "error", "scope", "alg", "format", "kind", "mode", "method", "version"]


def jvalue(sec, where, depth=0):
    k = rnd.randrange(11)
    if depth > 3 or k < 4:
        return rnd.choice([sec.any, sec.encoded])(where)
    if k == 4:
        return int(sec.digits(where))
    if k == 5:
        return rnd.choice([None, True, 3, 0.5, "", S + "/api/documents/" + sec.digits(where + " (url path)") + "?t=" + sec.opaque(where + " (url query)"),
                           "/api/x/" + sec.opaque(where + " (path)") + "/y", "2026-11-23", "2026-11-23T10:00:00Z"])
    if k in (6, 7):
        return [jvalue(sec, where + "[]", depth + 1) for _ in range(rnd.randrange(0, 4))]
    return jobject(sec, where, depth + 1)


def jobject(sec, where, depth=0):
    out = {}
    for _ in range(rnd.randrange(1, 5)):
        key = rnd.choice(JSON_KEYS)
        out[key] = jvalue(sec, f"{where}.{key}", depth)
    if rnd.random() < .3:
        key = rnd.choice(SHOWN)
        # A shown key holds a technical word; a sentence or an address under it is still a value.
        out[key] = rnd.choice([
            "new", "RS256", "Bearer", "invalid_grant",
            sec.free(f"{where}.{key} (free text under a shown key)"),
            sec.opaque(f"{where}.{key} (opaque value under a shown key)") + "@mil.gov.ua",
        ])
    return out


def query(sec, where):
    names = ["page", "since", "code", "state", "ticket", "token", "id", "q", "redirect_uri", "client_id",
             "session", "sig", "response_type", "scope"]
    parts = []
    for _ in range(rnd.randrange(1, 4)):
        n = rnd.choice(names)
        if n in ("response_type", "scope"):
            v = rnd.choice(["code", "openid", sec.free(f"{where} ?{n}= (free text under a shown key)")])
        elif n == "redirect_uri":
            v = S + "/cb/" + sec.digits(f"{where} ?redirect_uri path") + "?x=" + sec.opaque(f"{where} ?redirect_uri query")
        else:
            v = rnd.choice([sec.any, sec.encoded])(f"{where} ?{n}=")
        parts.append(f"{n}={quote(str(v), safe='')}" if rnd.random() < .9 else f"{n}={v}")
    if rnd.random() < .1:
        parts.append(sec.opaque(where + " (bare query word, no '=')"))
    return "&".join(parts)


def url(sec, where, host="sedo.mod.gov.ua"):
    segs = []
    for _ in range(rnd.randrange(1, 5)):
        segs.append(rnd.choice(["api", "documents", "inbox", "export", "auth", "kep", "v1", "callback", "users"])
                    if rnd.random() < .6 else rnd.choice([
                        sec.digits(where + " path segment"), sec.opaque(where + " path segment"),
                        quote(sec.text(where + " path segment")),
                        sec.opaque(where + " path segment") + ".zip",
                        "doc;jsessionid=" + sec.opaque(where + " path ;param"),
                        sec.opaque(where + " path segment") + "@mil.gov.ua"]))
    u = f"https://{host}/" + "/".join(segs)
    if rnd.random() < .6:
        u += "?" + query(sec, where)
    if rnd.random() < .15:
        u += "#" + rnd.choice([query(sec, where + " #fragment"), sec.opaque(where + " #fragment (bare)")])
    if rnd.random() < .05:
        u = u.replace("https://", "https://" + sec.word(where + " userinfo") + ":" + sec.opaque(where + " userinfo password") + "@")
    return u


def headers_req(sec, i):
    h = [("Host", "sedo.mod.gov.ua")]
    w = f"[{i}] request header"
    if rnd.random() < .6:
        cookies = [f"{rnd.choice(['SESSION', 'AUTH', 'lang', 'XSRF-TOKEN'])}={rnd.choice([sec.opaque, sec.encoded])(w + ' Cookie value')}"
                   for _ in range(rnd.randrange(1, 4))]
        if rnd.random() < .1:
            cookies.append(sec.opaque(w + " Cookie without '='"))
        h.append(("Cookie", "; ".join(cookies)))
    if rnd.random() < .4:
        tok = rnd.choice([sec.opaque, sec.encoded])(w + " Authorization credential")
        h.append((rnd.choice(["Authorization", "authorization", "Proxy-Authorization"]), rnd.choice([
            f"Bearer {tok}", f"Basic {base64.b64encode(('user:' + tok).encode()).decode()}", f"bearer  {tok}",
            sec.opaque(w + " Authorization WITHOUT a scheme"),
            f"Token token={tok}", f"Digest username=\"{sec.word(w + ' Authorization Digest username')}\", response=\"{tok}\"",
            f"Bearer\t{sec.opaque(w + ' Authorization after a TAB')}"])))
    for name in ("X-XSRF-TOKEN", "X-Auth-Token", "X-Api-Key", "X-Session-Id", "X-Signature"):
        if rnd.random() < .15:
            h.append((name, rnd.choice([sec.any, sec.encoded])(f"{w} {name}")))
    if rnd.random() < .3:
        h.append((rnd.choice(["Referer", "Origin"]), url(sec, w + " Referer")))
    if rnd.random() < .1:
        h.append((rnd.choice(["X-User", "X-Forwarded-User", "From", "X-Real-Name"]), sec.text(w + " (plain header)")))
    return h


def headers_resp(sec, i):
    h = []
    w = f"[{i}] response header"
    for _ in range(rnd.randrange(0, 3)):
        attrs = rnd.sample(["Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age=3600",
                            "Domain=" + rnd.choice(["sedo.mod.gov.ua", sec.by_design(w + " Set-Cookie Domain") + ".example"]),
                            "Path=/u/" + sec.digits(w + " Set-Cookie Path"),
                            "Expires=Wed, 21 Oct 2026 07:28:00 GMT",
                            sec.opaque(w + " Set-Cookie unknown attribute"),
                            "Priority=" + sec.opaque(w + " Set-Cookie unknown attribute value")], rnd.randrange(0, 4))
        cookie = f"{rnd.choice(['SESSION', 'AUTH', 'TS01'])}={rnd.choice([sec.opaque, sec.encoded])(w + ' Set-Cookie value')}"
        if rnd.random() < .08:
            cookie = sec.opaque(w + " Set-Cookie without '='")
        h.append(("Set-Cookie", "; ".join([cookie] + attrs)))
    if rnd.random() < .35:
        h.append((rnd.choice(["Location", "Content-Location"]), rnd.choice([
            url(sec, w + " Location"), url(sec, w + " Location", "id.gov.ua"),
            "/auth/cb?" + query(sec, w + " Location"), "cb/" + sec.digits(w + " relative Location"),
            "?" + query(sec, w + " Location"), "//id.gov.ua/x?" + query(sec, w + " Location"),
            "javascript:" + sec.opaque(w + " Location javascript:"),
            "https://id.gov.ua\\@" + sec.by_design(w + " Location host") + ".example/"])))
    if rnd.random() < .2:
        fn = rnd.choice([sec.text, sec.digits, sec.opaque])(w + " Content-Disposition filename")
        h.append(("Content-Disposition", rnd.choice([
            f'attachment; filename="{fn}.zip"', f"attachment; filename*=UTF-8''{quote(fn)}.p7s",
            f"attachment; filename={fn}.zip", f'inline; name="{fn}"; filename="{fn}.pdf"',
            f'form-data; name="{sec.opaque(w + " Content-Disposition name")}"',
            f"attachment; filename=\"a;{fn}.{sec.opaque(w + ' Content-Disposition extension')}\""])))
    if rnd.random() < .15:
        h.append(("WWW-Authenticate", rnd.choice([
            'Bearer realm="sedo"', f'Bearer realm="{sec.text(w + " WWW-Authenticate realm")}"',
            f"Negotiate {sec.encoded(w + ' WWW-Authenticate token')}", sec.by_design(w + " WWW-Authenticate scheme")])))
    for name in ("X-CSRF-Token", "X-Auth-Token", "ETag-Session", "X-Request-Signature"):
        if rnd.random() < .12:
            h.append((name, rnd.choice([sec.any, sec.encoded])(f"{w} {name}")))
    return h


def body_and_type(sec, where):
    k = rnd.randrange(9)
    if k < 3:
        return json.dumps(jobject(sec, where + " JSON"), ensure_ascii=rnd.random() < .5).encode(), "application/json"
    if k == 3:
        pairs = [(rnd.choice(["login", "password", "nonce", "signature", "certificate", "comment", "csrf", "pin"]),
                  rnd.choice([sec.any, sec.encoded])(where + " form field")) for _ in range(rnd.randrange(1, 4))]
        return "&".join(f"{n}={quote(str(v), safe='')}" for n, v in pairs).encode(), "application/x-www-form-urlencoded"
    if k == 4:
        t = sec.text(where + " HTML text")
        html = (f"<html><head><title>{t}</title><script src='/static/eusign.{sec.by_design(where + ' script name hash')}.js'></script>"
                f"<script src=\"/js/sign-{sec.by_design(where + ' script name')}.js?v={sec.opaque(where + ' script query')}\"></script>"
                f"<meta http-equiv='refresh' content='0; url={url(sec, where + ' meta refresh')}'></head>"
                f"<body><form method=\"post\" action=\"/auth/kep?ticket={sec.opaque(where + ' form action query')}\">"
                f"<input type=\"hidden\" name=\"nonce\" value=\"{sec.opaque(where + ' input value')}\">"
                f"<input name=\"{rnd.choice(['login', sec.by_design(where + ' input NAME'), sec.digits(where + ' input NAME')])}\" value='{sec.word(where + ' input value')}'>"
                f"<form action='{url(sec, where + ' form action')}' method={sec.word(where + ' form method word')}>"
                f"<p>{sec.text(where + ' HTML text')}</p></form></body></html>")
        return html.encode(), "text/html; charset=utf-8"
    if k == 5:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for _ in range(rnd.randrange(1, 4)):
                zf.writestr(f"{sec.text(where + ' ZIP member name')}.{rnd.choice(['pdf', 'p7s', 'xml', sec.opaque(where + ' ZIP member extension')])}",
                            sec.text(where + " ZIP member content"))
            zf.comment = sec.opaque(where + " ZIP comment").encode()
        return buf.getvalue(), rnd.choice(["application/zip", "application/octet-stream"])
    if k == 6:
        return sec.text(where + " plain text body").encode(), rnd.choice(["text/plain", "application/javascript", None])
    if k == 7:
        b = "----b" + sec.opaque(where + " multipart boundary")
        part = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{sec.text(where + ' multipart filename')}.pdf\"\r\n"
                f"Content-Type: application/pdf\r\n\r\n{sec.text(where + ' multipart content')}\r\n--{b}\r\n"
                f"Content-Disposition: form-data; name=\"{sec.opaque(where + ' multipart field NAME')}\"\r\n\r\n{sec.opaque(where + ' multipart field')}\r\n--{b}--\r\n")
        return part.encode(), f"multipart/form-data; boundary={b}"
    # JSON that is not an object, or JSON with a non-JSON content type
    return json.dumps(rnd.choice([[jobject(sec, where + " JSON list")], sec.text(where + " JSON string"),
                                  int(sec.digits(where + " JSON number"))])).encode(), rnd.choice(["application/json", "text/plain", "application/problem+json"])


def http(start, headers, body=b"", ctype=None, encode=True):
    headers = list(headers)
    if ctype:
        headers.append(("Content-Type" if rnd.random() < .9 else "content-type", ctype))
    if body and encode:
        k = rnd.randrange(6)
        if k == 0:
            body = gzip.compress(body)
            headers.append(("Content-Encoding", "gzip"))
        elif k == 1:
            body = zlib.compress(body)
            headers.append(("Content-Encoding", "deflate"))
        if rnd.random() < .2:
            body = b"".join(f"{len(body[j:j + 37]):x}\r\n".encode() + body[j:j + 37] + b"\r\n" for j in range(0, len(body), 37)) + b"0\r\n\r\n"
            headers.append(("Transfer-Encoding", "chunked"))
    sep = "\r\n" if rnd.random() < .95 else "\n"
    return (start + sep + "".join(f"{n}: {v}{sep}" for n, v in headers) + sep).encode("utf-8", "replace") + body


def agent_call(sec, i):
    method = rnd.choice(["Initialize", "EnumKeyMediaDevices", "ReadPrivateKey", "EnumOwnCertificates", "GetOwnCertificate",
                         "Sign", "SignData", "SignHash", "GetHostInfo", "ChangePrivateKeyPassword", "ReadPrivateKeyBinary",
                         "SetRuntimeParameter", "ProtectDataByPassword", "CtxReadPrivateKey", "readprivatekey", "Login"])
    w = f"[{i}] agent {method}"
    params = [rnd.choice([sec.any, sec.encoded])(w + " param") for _ in range(rnd.randrange(0, 3))]
    if "rivate" in method or "assword" in method or method == "Login":
        params = [{"devIndex": 0, "typeIndex": 7, "keyMedia": sec.text(w + " device name")}, sec.digits(w + " PIN")]
    if rnd.random() < .2:
        params = {"password": sec.opaque(w + " named param password"), "data": sec.encoded(w + " named param")}
    req = {"jsonrpc": "2.0", "id": i, "method": method, "params": params}
    if rnd.random() < .2:
        req["session_id"] = sec.opaque(w + " session_id")
    result = rnd.choice([None, True, sec.encoded(w + " result"), jobject(sec, w + " result"),
                         [jobject(sec, w + " result[]")], sec.text(w + " result text")])
    resp = {"jsonrpc": "2.0", "id": i, "result": result} if rnd.random() < .8 else {
        "jsonrpc": "2.0", "id": i, "error": {"code": -32500, "message": sec.text(w + " error message"),
                                             "data": sec.opaque(w + " error data")}}
    c = http("POST /json-rpc HTTP/1.1", [("Host", "127.0.0.1:8081"), ("Origin", S)], json.dumps(req).encode(), "application/json", encode=False)
    s = http("HTTP/1.1 200 OK", [], json.dumps(resp, ensure_ascii=False).encode(), "application/json", encode=False)
    return c, s


def capture(sec):
    sessions = []
    for i in range(1, rnd.randrange(2, 9)):
        if rnd.random() < .25:
            sessions.append(agent_call(sec, i))
            continue
        host = rnd.choice(["sedo.mod.gov.ua", "sedo.mod.gov.ua", "id.gov.ua", "cdn.example.net"])
        method = rnd.choice(["GET", "GET", "POST", "PUT", "DELETE"])
        target = url(sec, f"[{i}] request URL", host)
        if rnd.random() < .5:
            target = target.split(host, 1)[1] or "/"                       # origin-form, Host header decides
        body, ctype = (body_and_type(sec, f"[{i}] request body") if method in ("POST", "PUT") else (b"", None))
        c = http(f"{method} {target} HTTP/1.1", headers_req(sec, i) if host != "cdn.example.net" else [("Host", host)], body, ctype)
        rbody, rtype = body_and_type(sec, f"[{i}] response body") if rnd.random() < .75 else (b"", None)
        status = rnd.choice(["200 OK", "200 OK", "302 Found", "401 Unauthorized", "400 " + sec.text(f"[{i}] status reason phrase"), "500"])
        s = http(f"HTTP/1.1 {status}", headers_resp(sec, i), rbody, rtype)
        sessions.append((c, s))
    return sessions


def encodings(v):
    """The forms a value could be echoed in."""
    b = v.encode()
    yield "as is", v
    yield "lower-cased", v.lower()
    yield "base64", base64.b64encode(b).decode().rstrip("=")
    yield "hex", b.hex()
    yield "percent-encoded", quote(v, safe="")


def run(i):
    sec = Secrets()
    sessions = capture(sec)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, (c, s) in enumerate(sessions, 1):
            zf.writestr(f"raw/{n}_c.txt", c)
            zf.writestr(f"raw/{n}_s.txt", s)
    path = TMP / "capture.saz"
    path.write_bytes(buf.getvalue())
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            fa.analyze(path)
    except Exception as e:
        finding("analyze(): " + tb_key(e), f"seed {SEED} case {i}", e)
        save(f"fiddler_crash_{SEED}_{i}.saz", buf.getvalue())
        return
    text = out.getvalue()
    low = text.lower()
    for value, where in sec.items:
        if len(value) < 6:
            continue
        for how, form in encodings(value):
            if len(form) >= 6 and (form in text or (how == "lower-cased" and form in low)):
                place = where.split("] ", 1)[-1]
                place = " ".join(w for w in place.split() if not w.startswith("["))
                place = re.sub(r"\b(JSON(?: list)?|result|param)[.\[]\S*", r"\1 value", place)
                place = re.sub(r"\?\w+=", "?name=", place)
                line = next((ln for ln in text.splitlines() if form in ln or form in ln.lower()), "")
                finding(f"value shown ({how if how != 'lower-cased' else 'as is'}): {place}", line.strip()[:260])
                # FUZZ_KEEP=<part of a finding's name>: keep the capture that showed it.
                if os.environ.get("FUZZ_KEEP", "\0") in place:
                    save(f"fiddler_leak_{SEED}_{i}.saz", buf.getvalue())
                    save(f"fiddler_leak_{SEED}_{i}.txt", f"{value!r} @ {where}\n{line}\n".encode("utf-8"))
                break


def fuzz_captures():
    for i in range(N):
        run(i)


if __name__ == "__main__":
    main("scripts/fiddler_analyze.py", fuzz_captures)
