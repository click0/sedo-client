"""Fuzz sedo/config.py: config files and PIN files as people (and editors) really save them."""
import codecs
import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import PIN, finding, main, tb_key, trap_logs  # noqa: E402
from strategies import SET  # noqa: E402
from hypothesis import given, settings, strategies as st  # noqa: E402

import sedo.config as cfg  # noqa: E402

# ── a TOML writer for arbitrary (wrongly typed) values ────────────────────────
bare = st.text(alphabet="abcdefghijklmnopqrstuvwxyz_-0123456789", min_size=1, max_size=8)
strs = st.one_of(st.sampled_from(["", "default", "auto", "opensc", "pkcs11", "virtual", "iit_agent", "01", "0a2b",
                                  "01\n", "0x80420031", "0x80420031\n", "0x0", "0x", "SEDO_PIN_X", "C:\\libs\\a.dll",
                                  "https://sedo.mod.gov.ua/", "https://[::1", "2026-11-23", "Користувач ЦСК",
                                  "login", "doc", "..", "\ufeff", "a b"]),
                 st.text(max_size=10))
scalars = st.one_of(strs, st.integers(-5, 70000), st.booleans(), st.floats(allow_nan=True, allow_infinity=True),
                    st.dates().map(lambda d: ("date", d.isoformat())))
values = st.recursive(scalars, lambda kids: st.one_of(st.lists(kids, max_size=3),
                                                      st.dictionaries(bare, kids, max_size=3)), max_leaves=5)


def tv(v):
    if isinstance(v, tuple) and v and v[0] == "date":
        return v[1]
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return {"inf": "inf", "-inf": "-inf", "nan": "nan"}.get(str(v), repr(v))
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(tv(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{json.dumps(k)} = {tv(x)}" for k, x in v.items()) + "}"
    raise TypeError(v)


def mostly(good, bad=values, odds=6):
    """The valid shape most of the time: one wrong value must not be drowned by five others."""
    return st.one_of(*([good] * odds), bad)


GOOD_FIELDS = {
    "backend": st.sampled_from(["auto", "opensc", "pkcs11", "virtual", "iit_agent"]),
    "module": st.just("C:\\libs\\a.dll"), "slot": st.integers(0, 3), "cert_id": st.sampled_from(["01", "0a2b"]),
    "cert_index": st.integers(0, 2), "key_file": st.just("Key-6.dat"), "mechanism": st.just("0x80420031"),
    "pin_env": st.just("SEDO_PIN_X"), "pin_file": st.just("pin.txt"), "pin": st.just(PIN),
}
profiles = mostly(st.fixed_dictionaries({}, optional={k: mostly(v) for k, v in GOOD_FIELDS.items()}))
names = st.sampled_from(["default", "login", "doc", "a.b", "", "ключ", "x y"])
docs = st.fixed_dictionaries({}, optional={
    "sedo": mostly(st.fixed_dictionaries({}, optional={"url": mostly(st.just("https://sedo.mod.gov.ua")),
                                                       "output": mostly(st.just("./downloads")),
                                                       "since": mostly(st.just("2026-11-23"))})),
    "keys": mostly(st.dictionaries(names, profiles, max_size=3)),
    "roles": mostly(st.dictionaries(st.sampled_from(["auth", "sign"]), mostly(names), max_size=2)),
})


def toml_text(doc):
    return "\n".join(f"{json.dumps(k)} = {tv(v)}" for k, v in doc.items()) + "\n"


TMP = Path(tempfile.mkdtemp(prefix="fzcfg-"))


def _load(base_text, local_text, raw=False):
    """load_config over two files; only ConfigError is an acceptable failure."""
    d = Path(tempfile.mkdtemp(dir=TMP))
    for name, text in ((cfg.CONFIG_BASE, base_text), (cfg.CONFIG_LOCAL, local_text)):
        if text is not None:
            (d / name).write_bytes(text if isinstance(text, bytes) else text.encode("utf-8", "surrogatepass"))
    try:
        return cfg.load_config(client_dir=d, env={})
    finally:
        shutil.rmtree(d, ignore_errors=True)


@settings(**SET)
@given(st.one_of(st.none(), docs), st.one_of(st.none(), docs))
def fuzz_load(base, local):
    trap = trap_logs()
    try:
        c = _load(None if base is None else toml_text(base), None if local is None else toml_text(local))
    except cfg.ConfigError as e:
        if PIN in str(e):
            finding("ConfigError message shows a PIN from the file", str(e))
        return
    except Exception as e:
        finding("load_config: " + tb_key(e), (base, local), e)
        return
    finally:
        if PIN in trap.text():
            finding("load_config logs a PIN from the file", trap.text()[:300])
    # What main() does next with a config that loaded.
    try:
        red = cfg.redacted(c)
        text = json.dumps(red, ensure_ascii=False)
    except Exception as e:
        finding("redacted()/--show-config: " + tb_key(e), (base, local), e)
        return
    pins = [p.pin for p in c.keys.values() if p.pin]
    for pin in pins:
        if pin and len(pin) > 3 and pin in text.replace("SEDO_PIN", ""):
            finding("--show-config prints a PIN", pin, text[:300])
    try:
        for role in cfg.ROLES:
            p = c.profile(role)
            assert isinstance(p.name, str) and p.backend in cfg.BACKENDS
            if p.cert_id is not None and not re.fullmatch(r"(?:[0-9a-f]{2})+", p.cert_id):
                finding("a cert_id that is not hex passes validation (goes to --id)", p.cert_id)
            if p.mechanism is not None and not re.fullmatch(r"0x[0-9A-Fa-f]{1,8}", p.mechanism):
                finding("a mechanism that is not 0x… passes validation (goes to --mechanism)", p.mechanism)
        c.distinct_profiles()
    except Exception as e:
        finding("a loaded Config breaks on use: " + tb_key(e), (base, local), e)


@settings(**SET)
@given(st.binary(max_size=60))
def fuzz_load_bytes(blob):
    try:
        _load(None, blob)
    except cfg.ConfigError:
        return
    except RecursionError:
        return
    except Exception as e:
        finding("load_config(raw bytes): " + tb_key(e), blob, e)


GOOD = ('[sedo]\nurl = "https://sedo.mod.gov.ua"\n\n[keys.login]\nbackend = "opensc"\n'
        "module = 'C:\\Program Files (x86)\\Institute of Informational Technologies\\Користувач ЦСК\\PKCS11_EKeyAlmaz1C.dll'\n"
        'cert_id = "01"\n\n[roles]\nauth = "login"\n')
ENCODINGS = [("utf-8", b""), ("utf-8 + BOM (Notepad, PowerShell 5 -Encoding UTF8)", codecs.BOM_UTF8),
             ("utf-16-le + BOM (PowerShell 5 '>' / Out-File)", codecs.BOM_UTF16_LE), ("cp1251 (ANSI Notepad)", b""),
             ("utf-8, CRLF", b"")]


def editors():
    """One valid config, saved the ways Windows tools save text."""
    want = _load(None, GOOD)
    for label, bom in ENCODINGS:
        text = GOOD.replace("\n", "\r\n") if "CRLF" in label else GOOD
        enc = label.split(" ")[0].rstrip(",")
        blob = bom + text.encode(enc)
        try:
            got = _load(None, blob)
        except cfg.ConfigError as e:
            msg = str(e).split(": ", 1)[-1]
            if "UTF-8" not in msg and "encoding" not in msg.lower() and "BOM" not in msg:
                finding(f"config_local.toml saved as {label}: error that does not name the cause", msg)
            continue
        except Exception as e:
            finding(f"config_local.toml saved as {label}: " + tb_key(e), label, e)
            continue
        if cfg.redacted(got)["keys"] != cfg.redacted(want)["keys"]:
            finding(f"config_local.toml saved as {label}: loads differently", cfg.redacted(got))


# ── PIN files ─────────────────────────────────────────────────────────────────
pin_chars = st.text(alphabet="0123456789abcXYZ#!$ %", min_size=1, max_size=10).filter(lambda s: s.strip() == s and s)
wrappers = st.sampled_from([
    ("as is", b"", "utf-8", ""), ("trailing LF", b"", "utf-8", "\n"), ("trailing CRLF", b"", "utf-8", "\r\n"),
    ("UTF-8 BOM", codecs.BOM_UTF8, "utf-8", "\r\n"), ("UTF-16-LE BOM", codecs.BOM_UTF16_LE, "utf-16-le", "\r\n"),
    ("UTF-16-BE BOM", codecs.BOM_UTF16_BE, "utf-16-be", "\n"), ("leading spaces", b"", "utf-8", " \n"),
    ("NUL at the end", b"", "utf-8", "\x00"), ("zero-width space after", b"", "utf-8", "\u200b\n"),
    ("NBSP after", b"", "utf-8", "\u00a0\n"), ("second line", b"", "utf-8", "\n# comment\n"),
])


@settings(**SET)
@given(pin_chars, wrappers)
def fuzz_pin_file(pin, wrapper):
    label, bom, enc, tail = wrapper
    path = TMP / "pin.txt"
    path.write_bytes(bom + (pin + tail).encode(enc))
    os.chmod(path, 0o600)
    profile = cfg.KeyProfile("login", pin_file=str(path))
    stdin, sys.stdin = sys.stdin, io.StringIO("")
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            got = cfg.resolve_profile_pin(profile, env={})
    except cfg.ConfigError:
        return                                   # refusing the file is safe: no attempt is spent
    except SystemExit:
        return
    except Exception as e:
        finding(f"pin_file ({label}): " + tb_key(e), label, e)
        return
    finally:
        sys.stdin = stdin
    if got != pin:
        # The token gets `got`; every wrong C_Login costs one of 15 attempts on an Almaz-1K.
        finding(f"pin_file ({label}): the PIN sent to the token is not the PIN in the file",
                (pin, got), f"file bytes {path.read_bytes()!r}")


if __name__ == "__main__":
    main("sedo/config.py", fuzz_load, fuzz_load_bytes, editors, fuzz_pin_file)
