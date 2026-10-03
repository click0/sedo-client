"""
Integration tests against a REAL PKCS#11 stack without a hardware token:
SoftHSM2 as the module, OpenSC's pkcs11-tool and the real PyKCS11 library.

What this proves that the unit tests (fake PyKCS11, canned pkcs11-tool
output) cannot:

- the real `pkcs11-tool` output formats (--list-mechanisms, --list-objects)
  are parsed, and --read-object / --sign honour --id;
- the real PyKCS11 API: getMechanismList returns NAMES, getMechanismInfo
  wants the name, C_Login / C_FindObjects / C_Sign / unload on a real module;
- signatures are genuine (verified with openssl against the token's public key);
- the whole SEDOClient.authorize() path with a real signer against a local
  HTTP stand-in for SEDO.

Not covered: DSTU 4145 mechanisms — SoftHSM has none; the mechanism choice on
IIT/Avtor tokens was confirmed live (see CHANGELOG, ST-338).

Skipped unless softhsm2, opensc and openssl are installed. CI installs them
(tests.yml, job integration-softhsm) and sets SEDO_REQUIRE_SOFTHSM=1 so a
missing tool fails instead of skipping.
"""

import base64
import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SOFTHSM = next((p for p in (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
) if Path(p).exists()), None)
TOOL = shutil.which("pkcs11-tool")
UTIL = shutil.which("softhsm2-util")
OPENSSL = shutil.which("openssl")
PIN = "1234"
DIGEST = hashlib.sha256(b"sedo challenge").digest()

_missing = [n for n, v in (("libsofthsm2.so", SOFTHSM), ("pkcs11-tool", TOOL),
                           ("softhsm2-util", UTIL), ("openssl", OPENSSL)) if not v]
if _missing and os.environ.get("SEDO_REQUIRE_SOFTHSM"):
    pytest.fail(f"SEDO_REQUIRE_SOFTHSM is set but missing: {', '.join(_missing)}")
pytestmark = pytest.mark.skipif(bool(_missing), reason=f"needs {', '.join(_missing)}")


def _run(cmd, **kw):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    assert r.returncode == 0, f"{cmd[0]} failed:\n{r.stdout}\n{r.stderr}"
    return r.stdout


def _rs_to_der(sig: bytes) -> bytes:
    """Raw r||s ECDSA signature (what C_Sign returns) → DER SEQUENCE for openssl."""
    half = len(sig) // 2

    def integer(n: int) -> bytes:
        b = n.to_bytes((n.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(b)]) + b

    body = integer(int.from_bytes(sig[:half], "big")) + integer(int.from_bytes(sig[half:], "big"))
    return b"\x30" + bytes([len(body)]) + body


def _verify(pub_der: Path, digest: bytes, sig: bytes, tmp: Path) -> bool:
    """openssl pkeyutl -verify: the signature really came from this key."""
    d, s = tmp / "digest.bin", tmp / "sig.der"
    d.write_bytes(digest)
    s.write_bytes(_rs_to_der(sig))
    r = subprocess.run([OPENSSL, "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                        "-inkey", str(pub_der), "-in", str(d), "-sigfile", str(s)],
                       capture_output=True, text=True)
    return r.returncode == 0 and "Verified Successfully" in r.stdout


@dataclasses.dataclass
class Token:
    module: str
    dir: Path
    pub: dict        # CKA_ID hex → public key DER path
    cert: dict       # CKA_ID hex → certificate DER bytes


@pytest.fixture(scope="module")
def token(tmp_path_factory):
    """
    A fresh SoftHSM token with two EC key pairs (CKA_ID 01 "sign", 02 "enc")
    and a certificate object under each id — the shape of an Almaz-1K that
    carries a signing and an encryption pair.
    """
    d = tmp_path_factory.mktemp("softhsm")
    (d / "tokens").mkdir()
    conf = d / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {d / 'tokens'}\n"
                    "objectstore.backend = file\nlog.level = ERROR\n")
    saved = os.environ.get("SOFTHSM2_CONF")
    os.environ["SOFTHSM2_CONF"] = str(conf)   # read by the library at load time
    _run([UTIL, "--init-token", "--free", "--label", "SEDO-TEST",
          "--so-pin", "87654321", "--pin", PIN])
    pub, cert = {}, {}
    for cid, label in (("01", "sign"), ("02", "enc")):
        _run([TOOL, "--module", SOFTHSM, "--login", "--pin", PIN, "--keypairgen",
              "--key-type", "EC:prime256v1", "--id", cid, "--label", label])
        key = d / f"cert{cid}.key"
        der = d / f"cert{cid}.der"
        _run([OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key])
        _run([OPENSSL, "req", "-new", "-x509", "-key", key, "-subj", f"/CN={label}",
              "-days", "1", "-outform", "DER", "-out", der])
        _run([TOOL, "--module", SOFTHSM, "--login", "--pin", PIN, "--write-object", der,
              "--type", "cert", "--id", cid, "--label", f"{label}-cert"])
        pub[cid] = d / f"pub{cid}.der"
        _run([TOOL, "--module", SOFTHSM, "--read-object", "--type", "pubkey",
              "--id", cid, "-o", pub[cid]])
        cert[cid] = der.read_bytes()
    try:
        yield Token(SOFTHSM, d, pub, cert)
    finally:
        if saved is None:
            os.environ.pop("SOFTHSM2_CONF", None)
        else:
            os.environ["SOFTHSM2_CONF"] = saved


# ═══ 1. OpenSC backend against the real pkcs11-tool ═══════════════════════

class TestOpenSC:
    def _signer(self, token, **kw):
        from opensc_signer import OpenSCSigner
        return OpenSCSigner(module_path=token.module, pkcs11_tool=TOOL,
                            mechanism="ECDSA", **kw)

    def test_real_list_mechanisms_output_is_parsed(self, token):
        s = self._signer(token)
        lines = s.list_mechanisms()
        assert any(line.strip().startswith("ECDSA,") for line in lines), lines[:5]
        ids = s.sign_mechanism_ids()           # SoftHSM has no unnamed sign mechs
        assert isinstance(ids, list) and all(isinstance(i, int) for i in ids)

    def test_certificate_is_selected_by_id(self, token):
        s = self._signer(token)
        s.login(PIN)
        assert s.get_certificate() == token.cert["01"]
        assert s.get_certificate("02") == token.cert["02"]

    def test_signature_comes_from_the_certificates_key(self, token, tmp_path):
        """--sign --id <cert id>: the key that signs is the certificate's key."""
        s = self._signer(token)
        s.login(PIN)
        sig = s.sign(DIGEST)
        assert len(sig) == 64
        assert _verify(token.pub["01"], DIGEST, sig, tmp_path)
        assert not _verify(token.pub["02"], DIGEST, sig, tmp_path)

        s2 = self._signer(token, cert_id="02")
        s2.login(PIN)
        assert _verify(token.pub["02"], DIGEST, s2.sign(DIGEST), tmp_path)

    def test_cka_id_is_detected_from_the_token(self, token, tmp_path, caplog):
        """
        No cert_id given: the pair is read from --list-objects. Both SoftHSM
        pairs can sign, so the first (01) wins with a warning — and the
        signature really comes from key 01.
        """
        from opensc_signer import OpenSCSigner
        s = OpenSCSigner(module_path=token.module, pkcs11_tool=TOOL, mechanism="ECDSA")
        s.login(PIN)
        assert s.resolve_cert_id() == "01"
        assert "Several key/certificate pairs" in caplog.text
        assert s.get_certificate() == token.cert["01"]
        assert _verify(token.pub["01"], DIGEST, s.sign(DIGEST), tmp_path)

    def test_wrong_pin_is_a_runtimeerror_without_the_pin(self, token):
        s = self._signer(token)
        s.login("0000")
        with pytest.raises(RuntimeError, match="list-objects failed") as e:
            s.list_objects()
        assert "0000" not in str(e.value)

    def test_list_objects_shows_ids(self, token):
        s = self._signer(token)
        s.login(PIN)
        out = s.list_objects()
        assert "Private Key Object" in out and "ID:         01" in out and "ID:         02" in out

    def test_cli_reads_sedo_module_and_sedo_pin(self, token, tmp_path):
        env = dict(os.environ, SEDO_MODULE=token.module, SEDO_PIN=PIN,
                   PYTHONIOENCODING="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "opensc_signer.py"),
                            "--pkcs11-tool", TOOL, "--list-objects"],
                           capture_output=True, text=True, env=env, cwd=tmp_path)
        assert r.returncode == 0, r.stderr
        assert "ID:         01" in r.stdout

    def test_cli_empty_pin_exits_2_without_touching_the_token(self, token, tmp_path):
        env = {k: v for k, v in os.environ.items() if k != "SEDO_PIN"}
        env.update(SEDO_MODULE=token.module, PYTHONIOENCODING="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "opensc_signer.py"),
                            "--pkcs11-tool", TOOL, "--list-objects"],
                           capture_output=True, text=True, env=env, cwd=tmp_path,
                           stdin=subprocess.DEVNULL)      # getpass → EOF → ""
        assert r.returncode == 2, r.stderr
        assert "Empty PIN" in r.stderr
        assert "Private Key Object" not in r.stdout


# ═══ 2. PyKCS11 backends against the real library ═════════════════════════

pykcs11 = pytest.importorskip("PyKCS11", reason="pip install .[pkcs11]")


class TestPyKCS11:
    def _signer(self, token):
        from pkcs11_signer import PKCS11Signer
        return PKCS11Signer(token.module)

    def test_real_mechanism_list(self, token):
        s = self._signer(token)
        try:
            mechs = s.list_mechanisms()
        finally:
            s.close()
        by_name = {m["name"]: m for m in mechs}
        assert "CKM_ECDSA" in by_name, sorted(by_name)[:10]
        assert by_name["CKM_ECDSA"]["id"] == 0x1041 and by_name["CKM_ECDSA"]["can_sign"]
        assert all(isinstance(m["id"], int) for m in mechs)

    def test_login_pairs_key_and_certificate_by_cka_id(self, token):
        s = self._signer(token)
        try:
            s.login(PIN)
            kid = bytes(s._session.getAttributeValue(s._priv_key, [pykcs11.CKA_ID])[0])
            cid = bytes(s._session.getAttributeValue(s._cert_obj, [pykcs11.CKA_ID])[0])
            assert kid == cid
            assert s.get_certificate() == token.cert[kid.hex()]
            assert isinstance(s._sign_mechanism, int)   # tier-3 pick on a non-DSTU token
        finally:
            s.close()

    def test_signature_verifies_with_the_paired_public_key(self, token, tmp_path):
        s = self._signer(token)
        try:
            s.login(PIN)
            kid = bytes(s._session.getAttributeValue(s._priv_key, [pykcs11.CKA_ID])[0])
            sig = s.sign(DIGEST, mechanism=pykcs11.CKM_ECDSA)
        finally:
            s.close()
        assert len(sig) == 64
        assert _verify(token.pub[kid.hex()], DIGEST, sig, tmp_path)

    def test_wrong_pin_raises_and_a_retry_still_works(self, token):
        s = self._signer(token)
        try:
            with pytest.raises(RuntimeError, match="CKR_PIN_INCORRECT"):
                s.login("0000")
            assert s._session is None
            s.login(PIN)                 # no leaked session blocks the retry
            assert s._session is not None
        finally:
            s.close()

    def test_sign_failure_is_a_runtimeerror(self, token):
        s = self._signer(token)
        try:
            s.login(PIN)
            with pytest.raises(RuntimeError, match="sign failed"):
                s.sign(DIGEST, mechanism=pykcs11.CKM_AES_CMAC)   # EC key, MAC mechanism
        finally:
            s.close()

    def test_close_then_a_fresh_load_works(self, token):
        s = self._signer(token)
        s.login(PIN)
        s.close()
        s2 = self._signer(token)
        try:
            s2.login(PIN)
        finally:
            s2.close()

    def test_virtual_signer_on_the_same_library(self, token):
        from virtual_signer import VirtualSigner
        v = VirtualSigner(module_path=token.module)
        try:
            v.login(PIN)
            assert isinstance(v._sign_mechanism, int)
            assert len(v.get_certificate()) > 100
        finally:
            v.close()

    def test_cli_list_mechanisms(self, token, tmp_path):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "pkcs11_signer.py"),
                            "--module", token.module, "--list-mechanisms"],
                           capture_output=True, text=True, env=env, cwd=tmp_path)
        assert r.returncode == 0, r.stderr
        assert "CKM_ECDSA" in r.stdout and "0x00001041" in r.stdout


# ═══ 3. SEDOClient.authorize() end to end against a local SEDO stand-in ═══

class _FakeSEDO(HTTPServer):
    """Answers the guessed KEP endpoints and verifies the signature for real."""

    def __init__(self, pub_der: Path, cert: bytes, tmp: Path):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.pub_der, self.cert, self.tmp = pub_der, cert, tmp
        self.verify_calls: list[dict] = []
        self.accepted = None


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._json(200, {})                       # /auth/login: no IdP redirect

    def do_POST(self):
        srv: _FakeSEDO = self.server
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/api/auth/kep/init":
            self._json(200, {"challenge": base64.b64encode(DIGEST).decode(),
                             "session_id": "s1"})
        elif self.path == "/api/auth/kep/verify":
            body = json.loads(raw)
            srv.verify_calls.append(body)
            sig = base64.b64decode(body["signature"])
            cert = base64.b64decode(body["certificate"])
            ok = cert == srv.cert and _verify(srv.pub_der, DIGEST, sig, srv.tmp)
            srv.accepted = ok
            self._json(200, {"authenticated": ok})
        else:
            self._json(404, {})


@pytest.fixture
def sedo(token, tmp_path):
    def start(pub_id: str):
        srv = _FakeSEDO(token.pub[pub_id], token.cert[pub_id], tmp_path)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        srv.url = f"http://127.0.0.1:{srv.server_address[1]}"
        servers.append(srv)
        return srv
    servers = []
    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


class TestEndToEnd:
    def test_opensc_backend_authorizes(self, token, sedo):
        from sedo_client import SEDOClient
        srv = sedo("01")
        with SEDOClient(sedo_url=srv.url, backend="opensc", module_path=token.module) as c:
            c.signer.set_mechanism("ECDSA")           # SoftHSM has no DSTU 4145
            c.authorize(PIN)
        assert srv.accepted is True
        assert srv.verify_calls[0]["session_id"] == "s1"

    def test_pkcs11_backend_authorizes(self, token, sedo):
        from sedo_client import SEDOClient
        with SEDOClient(sedo_url="http://127.0.0.1:1", backend="pkcs11",
                        module_path=token.module) as c:
            c.signer.login(PIN)
            kid = bytes(c.signer._session.getAttributeValue(c.signer._priv_key,
                                                            [pykcs11.CKA_ID])[0])
            srv = sedo(kid.hex())
            c.sedo_url = srv.url
            c.signer._sign_mechanism = pykcs11.CKM_ECDSA
            c.authorize(PIN)
        assert srv.accepted is True

    def test_server_rejection_is_not_reported_as_success(self, token, sedo):
        """Certificate 01 signed by key 02: the server says no, so must we."""
        from sedo_client import SEDOClient
        srv = sedo("02")                      # expects key/cert 02
        with SEDOClient(sedo_url=srv.url, backend="opensc", module_path=token.module) as c:
            c.signer.set_mechanism("ECDSA")   # cert_id stays "01"
            with pytest.raises(RuntimeError, match="All auth flows failed"):
                c.authorize(PIN)
        assert srv.accepted is False
