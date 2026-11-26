"""Fuzz sedo/opensc_signer.py: pkcs11-tool that prints and writes anything."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
from common import PIN, TMP, exc_chain_text, finding, main, tb_key, trap_logs  # noqa: E402
from strategies import SET, texts  # noqa: E402
from hypothesis import given, settings, strategies as st  # noqa: E402

import sedo.opensc_signer as osig  # noqa: E402
import sedo.mechanism_ids as mids  # noqa: E402
import sedo.client as sc  # noqa: E402

# Empty stand-ins: the signer only checks that both paths exist. common.TMP is
# also where the signer's own temp dirs go, so leftovers are ours alone.
TOOL = str(TMP / "pkcs11-tool")
MODULE = str(TMP / "PKCS11_EKeyAlmaz1C.module")
Path(TOOL).write_bytes(b"")
Path(MODULE).write_bytes(b"")

# ── text the real tool prints, and mutations of it ────────────────────────────
MECH_LINES = ["mechtype-0x80420031, keySize={163,509}, hw, sign, verify, EC F_2M, EC parameters, EC OID",
              "mechtype-0x80420032, keySize={163,509}, hw, sign, verify, EC F_2M",
              "mechtype-0x80420014, keySize={32,32}, sign, verify", "mechtype-0x352, sign",
              "mechanism-0x80420031, sign", "SHA-1, digest", "ECDSA, keySize={256,521}, hw, sign, verify",
              "mechtype-0x, sign", "mechtype-0xZZ, sign", "  mechtype-0x80420031 sign",
              "mechtype-0x80420031,sign", "mechtype-0x80420031, signature", "mechtype-0x" + "F" * 40 + ", sign",
              "Supported mechanisms:", "", "mechtype-0x80420021, digest", "mechtype-0x80420031, keySize, SIGN"]
OBJ_LINES = ["Private Key Object; EC", "Certificate Object; type = X.509 cert", "Public Key Object; EC  EC_POINT 431 bits",
             "Data Object", "Secret Key Object; AES", "  label:      key 1", "  ID:         01", "  ID:         0A2B",
             "  ID:", "  ID:         --login", "  ID:         01 02", "  Usage:      decrypt, sign, signRecover, unwrap",
             "  Usage:      decrypt, unwrap", "  Usage:", "  Access:     sensitive, always sensitive, never extractable",
             "  subject:    DN: CN=Тест", "ID: 05", "\tID: 07", "  id: 09", "  ID:01", " ID :  03", "",
             "Using slot 0 with a present token (0x0)", "  label:      ID: 99", "  ID:         ٠١"]
junk = st.one_of(texts, st.text(max_size=30), st.binary(max_size=20).map(lambda b: b.decode("utf-8", "replace")))


def texts(lines):
    return st.lists(st.one_of(st.sampled_from(lines), junk), max_size=10).map("\n".join)


@settings(**SET)
@given(texts(MECH_LINES))
def fuzz_parse_mechanisms(text):
    try:
        ids = osig.parse_sign_mechanisms(text.splitlines())
    except Exception as e:
        finding("parse_sign_mechanisms: " + tb_key(e), text, e)
        return
    if not all(isinstance(i, int) and i >= 0 for i in ids):
        finding("parse_sign_mechanisms returns a non-id", text, ids)
    try:
        mech = mids.choose_sign_mechanism(ids)
    except ValueError:
        return
    except Exception as e:
        finding("choose_sign_mechanism: " + tb_key(e), ids, e)
        return
    if mech in mids.NON_SIGNATURE_MECHANISMS:
        finding("choose_sign_mechanism picks a MAC (burns a PIN attempt)", ids, hex(mech))
    if mech not in ids:
        finding("choose_sign_mechanism picks an id the token does not list", ids, hex(mech))
    if mech > 0xFFFFFFFF:
        finding("a mechanism id beyond 32 bits is chosen (CK_ULONG on Windows)", text, hex(mech))


@settings(**SET)
@given(texts(OBJ_LINES))
def fuzz_parse_objects(text):
    try:
        objs = osig.parse_objects(text)
        cid = osig.select_cert_id(objs)
    except Exception as e:
        finding("parse_objects/select_cert_id: " + tb_key(e), text, e)
        return
    if not re.fullmatch(r"(?:[0-9a-f]{2})+", cid):
        finding("select_cert_id returns something that is not a hex CKA_ID (goes to --id)", text, repr(cid))


# ── the signer over a fake subprocess ─────────────────────────────────────────
outputs = st.one_of(st.binary(max_size=40), texts(OBJ_LINES).map(lambda s: s.encode("utf-8", "replace")),
                    texts(MECH_LINES).map(lambda s: s.encode("utf-8", "replace")))
runs = st.fixed_dictionaries({
    "rc": st.sampled_from([0, 0, 0, 1, 2, -11, 255]),
    "stdout": outputs, "stderr": outputs,
    "file": st.one_of(st.none(), st.binary(max_size=30), st.just(b"")),      # what --output-file gets
    "raise": st.sampled_from([None, None, None, None, "timeout", "oserror"]),
})


class FakeRun:
    def __init__(self, script):
        self.script, self.cmds = list(script), []

    def __call__(self, cmd, input=None, capture_output=True, timeout=None, check=False):
        self.cmds.append(list(cmd))
        step = self.script.pop(0) if self.script else {"rc": 1, "stdout": b"", "stderr": b"", "file": None, "raise": None}
        if step["raise"] == "timeout":
            raise subprocess.TimeoutExpired(cmd, timeout, output=step["stdout"], stderr=step["stderr"])
        if step["raise"] == "oserror":
            raise OSError(8, "Exec format error")
        if "--output-file" in cmd and step["file"] is not None:
            Path(cmd[cmd.index("--output-file") + 1]).write_bytes(step["file"])
        return subprocess.CompletedProcess(cmd, step["rc"], step["stdout"], step["stderr"])


ALLOWED = (RuntimeError, subprocess.SubprocessError)


@settings(**SET)
@given(st.lists(runs, max_size=5), st.one_of(st.none(), st.just("01")))
def fuzz_signer(script, cert_id):
    fake = FakeRun(script)
    old = osig.subprocess.run
    osig.subprocess.run = fake
    trap = trap_logs()
    signer = osig.OpenSCSigner(module_path=MODULE, pkcs11_tool=TOOL, cert_id=cert_id)
    try:
        signer.login(PIN)
        cert = signer.get_certificate()
        sig = signer.sign(b"challenge")
        if not cert or not sig or not isinstance(cert, bytes) or not isinstance(sig, bytes):
            finding("OpenSCSigner returns an empty certificate/signature", script)
    except ALLOWED as e:
        if PIN in exc_chain_text(e):
            finding("OpenSCSigner: PIN reachable from the exception", type(e).__name__, exc_chain_text(e)[:300])
    except OSError as e:
        # An OSError from starting the tool itself ("Exec format error") is reported by main()
        # as it is; only one raised by the signer's own file handling is a finding.
        if e.errno != 8:
            finding("OpenSCSigner: " + tb_key(e) + " — not the RuntimeError contract authorize() relies on",
                    [{k: v for k, v in s.items()} for s in script], e)
    except Exception as e:
        finding("OpenSCSigner: " + tb_key(e), script, e)
    finally:
        osig.subprocess.run = old
        signer.logout()
    if PIN in trap.text():
        finding("OpenSCSigner: PIN in the log", trap.text()[:300])
    if "LOGGING ERROR" in trap.text():
        finding("OpenSCSigner: broken log call", trap.text()[:300])
    # --id must be a hex CKA_ID, and --mechanism what was configured.
    for cmd in fake.cmds:
        if "--id" in cmd:
            cid = cmd[cmd.index("--id") + 1]
            if not re.fullmatch(r"(?:[0-9a-f]{2})+", cid):
                finding("pkcs11-tool is run with --id that is not a hex CKA_ID", cid)
    leftovers = [p for p in Path(tempfile.gettempdir()).glob("sedo-*") if p.is_dir()]
    if leftovers:
        finding("OpenSCSigner leaves a temp dir behind", [str(p) for p in leftovers])
        for p in leftovers:
            shutil.rmtree(p, ignore_errors=True)


@settings(**SET)
@given(st.lists(runs, max_size=3))
def fuzz_discover(script):
    """_discover_opensc_mechanism: what the opensc backend does before login (no PIN)."""
    fake = FakeRun(script)
    old = osig.subprocess.run
    osig.subprocess.run = fake
    try:
        signer = osig.OpenSCSigner(module_path=MODULE, pkcs11_tool=TOOL)
        mech = sc.SEDOClient._discover_opensc_mechanism(signer, MODULE, "0x80420031")
        if not re.fullmatch(r"0x[0-9A-F]{8}", mech):
            finding("_discover_opensc_mechanism returns a bad --mechanism", [s["stdout"] for s in script], mech)
        elif int(mech, 16) in mids.NON_SIGNATURE_MECHANISMS:
            finding("_discover_opensc_mechanism picks a MAC", [s["stdout"] for s in script], mech)
    except Exception as e:
        finding("_discover_opensc_mechanism: " + tb_key(e), [s["stdout"] for s in script], e)
    finally:
        osig.subprocess.run = old


if __name__ == "__main__":
    main("sedo/opensc_signer.py", fuzz_parse_mechanisms, fuzz_parse_objects, fuzz_signer, fuzz_discover)
