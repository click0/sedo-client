"""
fiddler_analyze.py — розбирає Fiddler SAZ capture, виявляє auth flow СЕДО.

Вхід: sedo-auth-capture.saz (експорт Fiddler All Sessions → Save)
Вихід: хід входу і роботи з документами — лише СТРУКТУРА, без значень.

Звіт можна передавати: cookie, токени, коди OIDC, підписи, сертифікати,
PIN, ідентифікатори й вміст документів у ньому замасковано. Лишаються
методи й шляхи (ідентифікатори в шляху → {id}), назви параметрів, полів
JSON і cookie, типи та довжини значень, коди відповідей, Content-Type.
Значення показано лише для невеликих чисел і для технічних полів
(``_SHOWN_KEYS``: alg, status, response_type…).

Використання (Windows — PowerShell, з каталогу клієнта):
    .\\venv\\Scripts\\python.exe scripts\\fiddler_analyze.py sedo_login_reference.saz --output fiddler_report.txt

``--output`` пише UTF-8 напряму. Перенаправлення ``>`` у PowerShell
перекодовує вивід і псує кирилицю.
"""

import argparse
import base64
import binascii
import contextlib
import gzip
import io
import json
import re
import sys
import zipfile
import zlib
from collections import Counter
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qsl, unquote, urlsplit

# JSON-RPC methods whose params carry the token PIN. Duplicated from
# iit_client (scripts/ stays import-free of the package) — keep in sync.
_REDACTED_METHODS = frozenset({
    "ReadPrivateKey", "ReadPrivateKeyBinary", "ReadPrivateKeyFile",
    "ChangePrivateKeyPassword",
})

# Fields whose short string values are technical, not personal, and are what
# the flow has to be rebuilt from. Every other string shows as its shape only.
# Deliberately absent: state, nonce, code, token, id, title, name — values.
_SHOWN_KEYS = frozenset({
    "alg", "algorithm", "hashalgorithm", "hash_algorithm", "signalgorithm",
    "type", "token_type", "grant_type", "response_type", "response_mode",
    "scope", "status", "error", "format", "mode", "method", "kind",
    "encoding", "version", "content_type", "contenttype", "mimetype",
    "signatureformat", "signature_format", "signtype", "sign_type",
    "code_challenge_method", "jsonrpc",
})

_STATIC = re.compile(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp)$", re.I)
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?$")
_HEX = re.compile(r"^(?:[0-9a-fA-F]{2}){8,}$")
_B64 = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")
_JWT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$")
_WORD_SEGMENT = re.compile(r"^(?:[A-Za-z][A-Za-z_.-]{0,39}|v\d{1,2})$")
_SECRET_HEADER = re.compile(r"token|csrf|xsrf|auth|session|secret|signature|key", re.I)
# DER of OID 1.2.840.113549.1.7.2 (CMS SignedData) and the DSTU 4145 arc
# 1.2.804.2.1.1.1.1.3.1 — tell a CMS from a raw r||s signature.
_OID_CMS_SIGNED = bytes.fromhex("06092a864886f70d010702")
_OID_DSTU4145 = bytes.fromhex("2a86240201010101030101")
_MAX_DEPTH = 6
_MAX_KEYS = 40
_SMALL_INT = 1000


def parse_saz(saz_path: Path) -> list[dict]:
    """Парсить SAZ файл (ZIP с sessions всередині)."""
    sessions = []
    with zipfile.ZipFile(saz_path) as zf:
        # Session files: raw/<N>_c.txt (request), raw/<N>_s.txt (response)
        # N can be any number of digits (Fiddler does not always zero-pad).
        req_files = {}
        resp_files = {}
        for name in zf.namelist():
            m = re.match(r'raw/(\d+)_c\.txt$', name)
            if m:
                req_files[int(m.group(1))] = name
                continue
            m = re.match(r'raw/(\d+)_s\.txt$', name)
            if m:
                resp_files[int(m.group(1))] = name

        for num in sorted(req_files.keys() & resp_files.keys()):
            try:
                req_raw = zf.read(req_files[num])
                resp_raw = zf.read(resp_files[num])
            except KeyError:
                continue
            # The text form is for classification; bodies are parsed from the
            # bytes (gzip, ZIP exports and DER do not survive a utf-8 decode).
            sessions.append({"num": num,
                             "request": req_raw.decode("utf-8", errors="replace"),
                             "response": resp_raw.decode("utf-8", errors="replace"),
                             "request_raw": req_raw, "response_raw": resp_raw})
    return sessions


def classify_session(sess: dict) -> dict:
    """Класифікує сесію: localhost IIT agent / SEDO / OIDC / інше."""
    req = sess["request"]
    first_line = req.split("\n")[0].strip() if req else ""
    method_url = first_line

    classification = "other"
    host_match = re.search(r'Host:\s*([^\r\n]+)', req, re.I)
    host = host_match.group(1).strip() if host_match else ""

    if "127.0.0.1" in host or "localhost" in host:
        classification = "iit_agent"
    elif "sedo.mod.gov.ua" in host:
        classification = "sedo"
    elif "id.gov.ua" in host:
        classification = "oidc_idp"
    elif host.endswith("sedo.gov.ua"):
        classification = "sedo_old"

    return {
        "num": sess["num"],
        "class": classification,
        "method_url": method_url,
        "host": host,
        "request": req,
        "response": sess["response"],
        "request_raw": sess.get("request_raw", req.encode("utf-8")),
        "response_raw": sess.get("response_raw", sess["response"].encode("utf-8")),
    }


# ─── HTTP messages ───────────────────────────────────────────

def split_http(raw: bytes) -> tuple:
    """(start line, {lower name: [values]}, [(name as sent, value)], decoded body)."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    lines = head.decode("latin-1").splitlines()
    headers: dict = {}
    pairs = []
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if colon:
            headers.setdefault(name.strip().lower(), []).append(value.strip())
            pairs.append((name.strip(), value.strip()))
    return (lines[0].strip() if lines else ""), headers, pairs, _decode_body(headers, body)


def _dechunk(body: bytes) -> bytes:
    out, rest = bytearray(), body
    while rest:
        size_line, sep, rest = rest.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return body                     # not chunked after all
        if size == 0 or not sep:
            break
        out += rest[:size]
        rest = rest[size + 2:]
    return bytes(out)


def _decode_body(headers: dict, body: bytes) -> bytes:
    if "chunked" in " ".join(headers.get("transfer-encoding", [])).lower():
        body = _dechunk(body)
    encoding = " ".join(headers.get("content-encoding", [])).lower()
    try:
        if "gzip" in encoding:
            body = gzip.decompress(body)
        elif "deflate" in encoding:
            try:
                body = zlib.decompress(body)
            except zlib.error:
                body = zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, EOFError, zlib.error):
        pass                                 # keep the raw bytes, shape says what it is
    return body


# ─── Shapes: what a value is, never the value ────────────────

def _der_length_ok(b: bytes) -> bool:
    if len(b) < 2 or b[0] != 0x30:
        return False
    first = b[1]
    if first < 0x80:
        return 2 + first == len(b)
    n = first & 0x7F
    if not 1 <= n <= 4 or len(b) < 2 + n:
        return False
    return 2 + n + int.from_bytes(b[2:2 + n], "big") == len(b)


def bytes_kind(b: bytes) -> str:
    kind = f"{len(b)} bytes"
    if b[:4] == b"PK\x03\x04":
        return kind + ", zip"
    if b[:4] == b"%PDF":
        return kind + ", pdf"
    if _der_length_ok(b):
        kind += ", der"
        if _OID_CMS_SIGNED in b:
            kind += " cms-signed-data"
        if _OID_DSTU4145 in b:
            kind += " dstu4145"
    return kind


def _b64decode(s: str):
    padded = s + "=" * (-len(s) % 4)
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decode(padded.encode("ascii"))
        except (binascii.Error, ValueError):
            continue
    return None


def _jwt_shape(s: str) -> str:
    head, payload = s.split(".")[:2]
    try:
        header = json.loads(_b64decode(head) or b"")
        claims = json.loads(_b64decode(payload) or b"")
    except (ValueError, UnicodeDecodeError):
        return "jwt"
    alg = header.get("alg") if isinstance(header, dict) else None
    parts = []
    if isinstance(alg, str) and re.fullmatch(r"[A-Za-z0-9-]{2,16}", alg):
        parts.append(f"alg={alg}")
    if isinstance(claims, dict):
        parts.append("claims: " + ", ".join(_key(k) for k in claims))
    return "jwt(" + "; ".join(parts) + ")"


def _key(k) -> str:
    k = str(k)
    if _UUID.match(k) or re.search(r"\d{5,}", k) or len(k) > 40:
        return "<id>"
    return k


def str_shape(s: str, key=None) -> str:
    n = len(s)
    if (key and str(key).lower() in _SHOWN_KEYS and n <= 40
            and not re.search(r"\d{5,}", s) and "@" not in s):
        return json.dumps(s, ensure_ascii=False)
    if not s:
        return '""'
    if _DATE.match(s):
        return "date"
    if _DATETIME.match(s):
        return "datetime"
    if _UUID.match(s):
        return "uuid"
    if s.startswith(("http://", "https://")):
        return f"url({mask_url(s)})"
    if s.startswith("/") and " " not in s and n < 500:
        return f"path({mask_url(s)})"
    if _JWT.match(s):
        return _jwt_shape(s)
    if s.isdigit():
        return f"digits({n})"
    if _HEX.match(s):
        return f"hex({bytes_kind(bytes.fromhex(s))})"
    if _B64.match(s) and re.search(r"[0-9+/=_-]", s):
        decoded = _b64decode(s)
        if decoded is not None:
            return f"base64({bytes_kind(decoded)})"
    return f"str({n})"


def shape(v, key=None, depth=0) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v) if abs(v) < _SMALL_INT else "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return str_shape(v, key)
    if depth >= _MAX_DEPTH:
        return "…"
    if isinstance(v, list):
        if not v:
            return "[]"
        if len(v) <= 5 and not any(isinstance(x, (dict, list)) for x in v):
            return "[" + ", ".join(shape(x, key, depth + 1) for x in v) + "]"
        shapes: list = []
        for x in v:
            s = shape(x, key, depth + 1)
            if s not in shapes:
                shapes.append(s)
        if len(shapes) > 3:
            shapes = shapes[:3] + ["…"]
        return f"[{len(v)} × " + " | ".join(shapes) + "]"
    if isinstance(v, dict):
        items = list(v.items())
        parts = [f"{_key(k)}: {shape(x, k, depth + 1)}" for k, x in items[:_MAX_KEYS]]
        if len(items) > _MAX_KEYS:
            parts.append(f"…+{len(items) - _MAX_KEYS}")
        return "{" + ", ".join(parts) + "}"
    return type(v).__name__


# ─── URLs and headers ────────────────────────────────────────

def _segment(seg: str) -> str:
    seg = unquote(seg)
    if not seg:
        return ""
    if _UUID.match(seg):
        return "{uuid}"
    if _WORD_SEGMENT.match(seg):
        return seg
    return "{id}"


def mask_query(q: str) -> str:
    pairs = parse_qsl(q, keep_blank_values=True)
    if not pairs:
        return f"str({len(q)})" if q else ""
    out = []
    for k, v in pairs:
        value = v if v.isdigit() and int(v) < _SMALL_INT else str_shape(v, k)
        out.append(f"{_key(k)}={value}")
    return "&".join(out)


def _split(url: str):
    """urlsplit that never raises: "http://[::1" in a capture is a ValueError."""
    try:
        parts = urlsplit(url)
        parts.port                          # raises on "host:abc" too
        return parts
    except ValueError:
        return None


def mask_url(url: str) -> str:
    parts = _split(url.strip())
    if parts is None:
        return f"invalid-url({len(url)})"
    out = f"{parts.scheme}://" if parts.scheme else ""
    if parts.hostname:
        try:
            port = parts.port
        except ValueError:
            port = None
        out += parts.hostname + (f":{port}" if port else "")
    out += "/".join(_segment(s) for s in parts.path.split("/"))
    if parts.query:
        out += "?" + mask_query(parts.query)
    if parts.fragment:
        out += "#" + mask_query(parts.fragment)
    return out


def _cookie_attr(attr: str) -> str:
    name, _, value = attr.strip().partition("=")
    name = name.strip()
    if name.lower() == "path":
        return f"{name}={mask_url(value.strip())}"
    if name.lower() in ("domain", "samesite"):
        return f"{name}={value.strip()}"
    return name


def header_line(name: str, value: str):
    n = name.lower()
    if n == "content-type":
        return f"Content-Type: {value.split(';')[0].strip()}"
    if n in ("location", "origin", "referer", "content-location"):
        return f"{name}: {mask_url(value)}"
    if n == "cookie":
        names = [c.split("=", 1)[0].strip() for c in value.split(";") if c.strip()]
        return "Cookie: " + ", ".join(names)
    if n == "set-cookie":
        cookie, *attrs = value.split(";")
        attrs = [_cookie_attr(a) for a in attrs if a.strip()]
        return f"Set-Cookie: {cookie.split('=', 1)[0].strip()} ({'; '.join(attrs)})"
    if n in ("authorization", "proxy-authorization"):
        scheme, _, credential = value.partition(" ")
        return f"{name}: {scheme} {str_shape(credential.strip())}".rstrip()
    if n == "www-authenticate":
        return f"WWW-Authenticate: {value.split(' ')[0]}"
    if n == "content-disposition":
        m = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", value, re.I)
        suffix = PurePosixPath(unquote(m.group(1))).suffix if m else ""
        return f"Content-Disposition: {value.split(';')[0].strip()}" + (
            f"; filename=*{suffix}" if m else "")
    if _SECRET_HEADER.search(n):
        return f"{name}: {str_shape(value)}"
    return None


# ─── Bodies ──────────────────────────────────────────────────

def _zip_line(body: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = [i.filename for i in zf.infolist() if not i.is_dir()]
    except zipfile.BadZipFile:
        return f"zip (damaged), {len(body)} bytes"
    suffixes = Counter(PurePosixPath(n).suffix.lower() or "(no ext)" for n in names)
    listing = ", ".join(f"{s} ×{c}" for s, c in sorted(suffixes.items()))
    return f"zip, {len(body)} bytes: {len(names)} entries ({listing})"


def _html_line(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    out = [f"html, {len(body)} bytes"]
    for m in re.finditer(r"<form\b([^>]*)>", text, re.I):
        attrs = m.group(1)
        action = re.search(r"action\s*=\s*[\"']([^\"']*)", attrs, re.I)
        method = re.search(r"method\s*=\s*[\"']?(\w+)", attrs, re.I)
        out.append(f"form {method.group(1).upper() if method else 'GET'} "
                   f"{mask_url(action.group(1)) if action else '(this page)'}")
    inputs = []
    for m in re.finditer(r"<input\b([^>]*)>", text, re.I):
        name = re.search(r"name\s*=\s*[\"']([^\"']*)", m.group(1), re.I)
        kind = re.search(r"type\s*=\s*[\"']?(\w+)", m.group(1), re.I)
        if name:
            inputs.append(f"{_key(name.group(1))}({kind.group(1).lower() if kind else 'text'})")
    if inputs:
        out.append("inputs: " + ", ".join(inputs[:_MAX_KEYS]))
    refresh = re.search(r"http-equiv\s*=\s*[\"']refresh[\"'][^>]*url=([^\"'>]+)", text, re.I)
    if refresh:
        out.append(f"meta refresh → {mask_url(refresh.group(1))}")
    scripts = {PurePosixPath((_split(s) or _split("")).path).name
               for s in re.findall(r"<script\b[^>]*src\s*=\s*[\"']([^\"']+)", text, re.I)}
    signing = sorted(s for s in scripts if re.search(r"eusign|euscp|iit|sign|crypt", s, re.I))
    if signing:
        out.append("signing scripts: " + ", ".join(signing))
    return "; ".join(out)


def body_line(headers: dict, body: bytes):
    if not body:
        return None
    ctype = (headers.get("content-type") or [""])[0].split(";")[0].strip().lower()
    head = body.lstrip()[:16]
    if "json" in ctype or head[:1] in (b"{", b"["):
        try:
            return "JSON " + shape(json.loads(body.decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            pass
    if ctype == "application/x-www-form-urlencoded":
        return "form " + mask_query(body.decode("latin-1"))
    if body[:4] == b"PK\x03\x04":
        return _zip_line(body)
    if ctype.startswith("text/html") or head.lower().startswith((b"<!doctype html", b"<html")):
        return _html_line(body)
    if body[:4] == b"%PDF" or body[:1] == b"\x30":
        return bytes_kind(body)
    return f"{ctype or 'binary'}, {len(body)} bytes"


# ─── Links between values, without the values ───────────────
#
# What the agent signs and what SEDO gets back is the core of the flow. A
# string that reappears (as is, or the same bytes in base64 / hex) is shown as
# a reference to where it came from: "signature ← [6] SignData result".

def _forms(s: str) -> set:
    forms = {s.encode("utf-8")}
    if _HEX.match(s):
        forms.add(bytes.fromhex(s))
    if _B64.match(s):
        decoded = _b64decode(s)
        if decoded:
            forms.add(decoded)
    return {f for f in forms if len(f) >= 8}


def _strings(v, path=""):
    """(json path with masked keys, string) for every string inside v."""
    if isinstance(v, str):
        yield path, v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from _strings(x, f"{path}.{_key(k)}" if path else _key(k))
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from _strings(x, f"{path}[{i}]")


def _json(body: bytes):
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _request_strings(start: str, pairs: list, headers: dict, body: bytes) -> list:
    parts = start.split()
    target = (_split(parts[1]) if len(parts) > 1 else None) or _split("")
    # Path segments masked as {id}/{uuid}: which earlier field they come from
    # ("path {id} ← [10] documents[0].id").
    out = [(f"path {_segment(seg)}", unquote(seg)) for seg in target.path.split("/")
           if _segment(seg) in ("{id}", "{uuid}")]
    out += [(f"?{_key(k)}", v) for k, v in parse_qsl(target.query)]
    # Not Cookie: every request would link back to its Set-Cookie. Tokens and
    # CSRF headers are the interesting ones (Bearer ← a login response field).
    for name, value in pairs:
        if name.lower() in ("authorization", "proxy-authorization"):
            out.append((name, value.partition(" ")[2].strip()))
        elif name.lower() != "cookie" and _SECRET_HEADER.search(name):
            out.append((name, value))
    data = _json(body)
    if data is not None:
        out += list(_strings(data))
    elif "x-www-form-urlencoded" in " ".join(headers.get("content-type", [])):
        out += [(_key(k), v) for k, v in parse_qsl(body.decode("latin-1"))]
    return out


def _response_strings(headers: dict, body: bytes) -> list:
    out = []
    for cookie in headers.get("set-cookie", []):
        name, _, value = cookie.split(";")[0].partition("=")
        out.append((f"Set-Cookie {name.strip()}", value.strip()))
    for location in headers.get("location", []):
        split = _split(location) or _split("")
        out += [(f"Location?{_key(k)}", v)
                for k, v in parse_qsl(split.query) + parse_qsl(split.fragment)]
    data = _json(body)
    if data is not None:
        out += list(_strings(data))
    return out


class _Seen:
    """Byte forms of every string seen so far → where it first appeared."""

    def __init__(self):
        self._origin: dict = {}

    def add(self, label: str, strings):
        for path, value in strings:
            for form in _forms(value):
                self._origin.setdefault(form, f"{label} {path}".rstrip())

    def links(self, strings) -> list:
        out = []
        for path, value in strings:
            origin = next((self._origin[f] for f in _forms(value) if f in self._origin), None)
            if origin:
                out.append(f"{path or 'value'} ← {origin}")
        return out


# ─── Report sections ─────────────────────────────────────────

def _request_url(start: str, headers: dict) -> tuple:
    parts = start.split()
    method = parts[0] if parts else "?"
    target = parts[1] if len(parts) > 1 else ""
    if target.startswith("/"):
        host = (headers.get("host") or [""])[0]
        target = f"https://{host}{target}"
    return method, target


def flow_entry(s: dict, seen: "_Seen" = None) -> list:
    """Lines for one session: request and response, structure only."""
    seen = seen or _Seen()
    start, req_headers, req_pairs, req_body = split_http(s["request_raw"])
    method, url = _request_url(start, req_headers)
    lines = [f"[{s['num']:4}] {method} {mask_url(url)}"]
    for name, v in req_pairs:
        line = header_line(name, v)
        if line:
            lines.append(f"       > {line}")
    body = body_line(req_headers, req_body)
    if body:
        lines.append(f"       > {body}")
    lines += [f"       > {link}"
              for link in seen.links(_request_strings(start, req_pairs, req_headers, req_body))]
    status, resp_headers, resp_pairs, resp_body = split_http(s["response_raw"])
    code = " ".join(status.split()[1:]) if status.upper().startswith("HTTP/") else status
    lines.append(f"       < {code or '(no response)'}")
    for name, v in resp_pairs:
        line = header_line(name, v)
        if line:
            lines.append(f"       < {line}")
    body = body_line(resp_headers, resp_body)
    if body:
        lines.append(f"       < {body}")
    seen.add(f"[{s['num']}]", _response_strings(resp_headers, resp_body))
    return lines


def agent_entry(s: dict, seen: "_Seen" = None) -> str:
    """One line per JSON-RPC call; with `seen`, links to earlier values follow."""
    req_body = split_http(s["request_raw"])[3]
    try:
        payload = json.loads(req_body.decode("utf-8").strip())
    except (ValueError, UnicodeDecodeError):
        return f"  [{s['num']:4}] {mask_url(s['method_url'].split(' ')[1] if ' ' in s['method_url'] else '')}"
    if not isinstance(payload, dict):
        return f"  [{s['num']:4}] JSON {shape(payload)}"
    method = str(payload.get("method", "?"))
    # Never echo params of PIN-carrying methods from a capture.
    secret = method in _REDACTED_METHODS
    params = "[***]" if secret else shape(payload.get("params", []))
    line = f"  [{s['num']:4}] {method}({params})"
    links = []
    if seen is not None and not secret:
        links = [f"params{link}" for link in seen.links(_strings(payload.get("params", [])))]
    answer = _json(split_http(s["response_raw"])[3].strip())
    if isinstance(answer, dict) and "error" in answer:
        line += f" → error {shape(answer['error'])}"
    elif isinstance(answer, dict) and "result" in answer:
        line += f" → {shape(answer['result'])}"
        if seen is not None:
            seen.add(f"[{s['num']}] {method} result", _strings(answer["result"]))
    return line + "".join(f"\n         {link}" for link in links)


def _is_static(s: dict) -> bool:
    parts = s["method_url"].split()
    return len(parts) > 1 and bool(_STATIC.search((_split(parts[1]) or _split("")).path))


def analyze(saz_path: Path):
    print(f"Analyzing: {Path(saz_path).name}")
    print("Лише структура: значення (cookie, токени, коди, підписи, сертифікати, PIN,\n"
          "ідентифікатори й вміст документів) замасковано. Звіт можна передавати.")
    sessions = parse_saz(saz_path)
    print(f"Total HTTP sessions: {len(sessions)}")

    classified = [classify_session(s) for s in sessions]
    categories = {}
    for s in classified:
        categories.setdefault(s["class"], []).append(s)

    print("\n=== Категорії ===")
    for cat, items in categories.items():
        print(f"  {cat}: {len(items)}")
    other_hosts = Counter(s["host"].split(":")[0] for s in categories.get("other", []) if s["host"])
    if other_hosts:
        print("Інші хости: " + ", ".join(f"{h} ×{c}" for h, c in other_hosts.most_common(15)))

    # ─── IIT Agent calls ─────────────────────────────────────
    iit = categories.get("iit_agent", [])
    if iit:
        print(f"\n=== IIT Agent JSON-RPC calls ({len(iit)}) ===")
        print("Послідовність викликів (method(params) → result), лише структура:")
        for s in iit[:60]:
            print(agent_entry(s))

    # ─── SEDO calls ──────────────────────────────────────────
    sedo = categories.get("sedo", []) + categories.get("sedo_old", [])
    urls = set()
    if sedo:
        print(f"\n=== SEDO server calls ({len(sedo)}) ===")
        print("Унікальні URL-и:")
        for s in sedo:
            m = re.match(r'(\w+)\s+(\S+)', s["method_url"])
            if m and m.group(1) != "CONNECT" and not _is_static(s):
                urls.add(f"{m.group(1)} {mask_url(m.group(2))}")
        for u in sorted(urls):
            print(f"  {u}")

    # ─── OIDC ────────────────────────────────────────────────
    oidc = categories.get("oidc_idp", [])
    if oidc:
        print(f"\n=== OIDC redirect (id.gov.ua) — {len(oidc)} calls ===")
        print("Це означає СЕДО використовує OIDC flow!")
        for s in oidc[:5]:
            parts = s["method_url"].split()
            print(f"  [{s['num']:4}] {parts[0] if parts else '?'} "
                  f"{mask_url(parts[1]) if len(parts) > 1 else ''}")

    # ─── The flow, request by request ────────────────────────
    flow = [s for s in classified
            if s["class"] in ("sedo", "sedo_old", "oidc_idp", "iit_agent")
            and not s["method_url"].startswith("CONNECT")]
    static = [s for s in flow if _is_static(s)]
    flow = [s for s in flow if not _is_static(s)]
    if flow:
        print(f"\n=== Хід: СЕДО, id.gov.ua і агент ІІТ, запит за запитом ({len(flow)}) ===")
        print("> запит, < відповідь. Значення показано лише для невеликих чисел і полів:")
        print("  " + ", ".join(sorted(_SHOWN_KEYS)))
        print("«x ← [N] y»: значення x те саме, що y у сесії N (як є, base64 чи hex).")
        if static:
            print(f"(пропущено статику .js/.css/зображення: {len(static)})")
        seen = _Seen()
        for s in flow:
            if s["class"] == "iit_agent":
                print(agent_entry(s, seen).strip().replace("] ", "] агент ", 1))
            else:
                print("\n".join(flow_entry(s, seen)))

    # ─── Висновок ────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("РЕКОМЕНДАЦІЯ для sedo_client.py:")
    print("=" * 60)

    if oidc:
        print("""
СЕДО використовує OIDC через id.gov.ua.
→ Реалізувати _flow_oidc() з кодом для:
   1. GET /auth/login → отримати redirect на id.gov.ua
   2. На id.gov.ua викликати EUSignAgent JSON-RPC напряму
   3. Отримати id_token / code → передати на sedo.mod.gov.ua
""")
    elif iit and sedo:
        print("""
СЕДО викликає EUSignAgent напряму (direct KEP flow).
→ Реалізувати _flow_direct_kep() або _flow_cms_post() з URL:""")
        for u in sorted(urls)[:10]:
            print(f"     {u}")
    else:
        print("Не вдалося однозначно класифікувати. Перевірте SAZ вручну.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Structure of the SEDO login flow from a Fiddler SAZ capture, "
                    "with every value masked")
    ap.add_argument("saz", type=Path, help="Fiddler capture (File → Save → All Sessions)")
    ap.add_argument("-o", "--output", type=Path,
                    help="write the report here as UTF-8 (PowerShell '>' re-encodes it)")
    args = ap.parse_args(argv)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f, contextlib.redirect_stdout(f):
            analyze(args.saz)
        print(f"Report: {args.output}")
        return 0
    # An interactive Windows console prints Unicode itself (PEP 528); a
    # redirect is what breaks the Cyrillic, and --output is the cure for that.
    analyze(args.saz)
    return 0


if __name__ == "__main__":
    sys.exit(main())
