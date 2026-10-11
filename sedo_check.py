"""
Перевірка налаштувань без PIN: ``sedo_client.py --check``.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.31
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026

Для кожного профілю з конфігу: чи є модуль і якої він бітності, чи знайдено
pkcs11-tool тієї ж бітності, чи видно токен, який механізм підпису буде
обрано, які сертифікати (CKA_ID) є на токені і чи серед них той, що в
``cert_id``, звідки візьметься PIN. Жодного C_Login: усе це доступно без PIN,
тож перевірка не коштує жодної з 15 спроб Алмаз-1К.

Замінює ручний прогін команд на машині з токеном: один виклик, вивід можна
переслати як є.
"""

import logging
import os
import struct
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

__all__ = ["run_checks", "check_profile", "pe_bitness", "python_bitness", "Report"]

OK, WARN, FAIL = "✓", "!", "✗"


class Report:
    """Collects (level, text) lines; ``ok`` is False after any FAIL."""

    def __init__(self):
        self.lines: list = []

    def add(self, level: str, text: str) -> None:
        self.lines.append((level, text))

    @property
    def ok(self) -> bool:
        return not any(level == FAIL for level, _ in self.lines)

    @property
    def problems(self) -> int:
        return sum(1 for level, _ in self.lines if level in (WARN, FAIL))

    def render(self) -> str:
        return "\n".join(f"  {level} {text}" if level else text for level, text in self.lines)


def pe_bitness(path) -> Optional[int]:
    """32 / 64 for a PE file, None for anything else (ELF, missing, garbage)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return None
            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            fh.seek(e_lfanew)
            pe = fh.read(6)
    except OSError:
        return None
    if pe[:4] != b"PE\0\0":
        return None
    machine = struct.unpack_from("<H", pe, 4)[0]
    return {0x014C: 32, 0x8664: 64, 0xAA64: 64, 0x01C4: 32}.get(machine)


def python_bitness() -> int:
    return 64 if sys.maxsize > 2 ** 32 else 32


def _bits(path) -> str:
    b = pe_bitness(path)
    return f"{b}-bit" if b else "не PE"


def _module_for(profile):
    """(path or None, how it was found)."""
    if profile.module:
        return profile.module, "з конфігу"
    env = os.environ.get("SEDO_MODULE")
    if env:
        return env, "$SEDO_MODULE"
    try:
        if profile.backend == "virtual":
            from virtual_signer import VirtualSigner
            return VirtualSigner._find_module(), "автопошук"
        from pkcs11_signer import PKCS11Signer
        return PKCS11Signer._find_module(), "автопошук"
    except FileNotFoundError:
        return None, "автопошук"


def _pin_source(profile, is_auth_key: bool) -> tuple:
    from _console import PIN_ENV
    if profile.pin:
        return WARN, "PIN записано у файлі конфігу (краще pin_env або pin_file)"
    var = profile.effective_pin_env
    if os.environ.get(var):
        return OK, f"PIN: ${var} задано"
    if is_auth_key and os.environ.get(PIN_ENV):
        return OK, f"PIN: ${PIN_ENV} задано (${var} — ні)"
    if profile.pin_file:
        p = Path(profile.pin_file).expanduser()
        return (OK, f"PIN: файл {p}") if p.is_file() else (FAIL, f"PIN: файл {p} не існує")
    return WARN, f"PIN: ні ${var}" + (f", ні ${PIN_ENV}" if is_auth_key else "") + " — буде інтерактивний запит"


def _check_opensc(profile, module: str, rep: Report) -> None:
    import subprocess
    from mechanism_ids import choose_sign_mechanism
    from opensc_signer import OpenSCNotFound, OpenSCSigner, parse_objects
    try:
        tool = OpenSCSigner._find_tool()
    except OpenSCNotFound as e:
        rep.add(FAIL, f"pkcs11-tool не знайдено: {e}")
        return
    tb, mb = pe_bitness(tool), pe_bitness(module)
    if tb and mb and tb != mb:
        rep.add(FAIL, f"pkcs11-tool {tool} — {tb}-bit, а модуль {mb}-bit: "
                      f"LoadLibrary не вдасться (sc_dlopen failed). Потрібен OpenSC {mb}-bit")
    else:
        rep.add(OK, f"pkcs11-tool: {tool} ({_bits(tool)})")
    try:
        signer = OpenSCSigner(module_path=module, pkcs11_tool=tool,
                              mechanism=profile.mechanism or "0x80420031", cert_id=profile.cert_id)
        slots = signer.list_slots()
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        rep.add(FAIL, f"pkcs11-tool --list-slots: {e}")
        return
    tokens = [ln.strip() for ln in slots.splitlines() if "token label" in ln]
    if not tokens:
        rep.add(FAIL, "токен не видно (--list-slots без token label): підключений? SCardSvr запущений?")
        return
    rep.add(OK, "токен: " + "; ".join(tokens))
    try:
        ids = signer.sign_mechanism_ids()
        mech = profile.mechanism or f"0x{choose_sign_mechanism(ids):08X}"
        rep.add(OK, f"механізм підпису: {mech}" + (" (зафіксовано в конфігу)" if profile.mechanism
                                                     else " (зі списку токена)"))
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as e:
        rep.add(FAIL, f"механізм підпису не визначено: {e}")
    try:
        out = signer._run(["--list-objects", "--type", "cert"])      # public objects, no PIN
        certs = [o["id"] for o in parse_objects(out.stdout.decode("utf-8", "replace"))
                 if o["kind"] == "certificate" and o["id"]]
    except (OSError, subprocess.SubprocessError) as e:
        rep.add(WARN, f"сертифікати не прочитано: {e}")
        return
    _report_certs(profile, certs, rep)


def _report_certs(profile, certs: list, rep: Report) -> None:
    if not certs:
        rep.add(WARN, "сертифікатів у публічній частині токена не видно; CKA_ID перевіриться лише з PIN")
        return
    shown = ", ".join(certs)
    if profile.cert_id:
        if profile.cert_id in certs:
            rep.add(OK, f"сертифікати: {shown}; cert_id {profile.cert_id} присутній")
        else:
            rep.add(FAIL, f"сертифікати: {shown}; cert_id {profile.cert_id} НЕМАЄ на токені")
    else:
        rep.add(OK, f"сертифікати: {shown}; cert_id не задано — пара обереться автоматично")


def _check_pykcs11(profile, module: str, rep: Report) -> None:
    try:
        import PyKCS11
    except ImportError:
        rep.add(FAIL, "PyKCS11 не встановлено (pip install .[pkcs11]); або backend = \"opensc\"")
        return
    mb = pe_bitness(module)
    if mb and mb != python_bitness():
        rep.add(FAIL, f"модуль {mb}-bit, а Python {python_bitness()}-bit: PyKCS11 його не завантажить. "
                      f"Потрібен Python {mb}-bit або backend = \"opensc\"")
        return
    from pkcs11_signer import iter_mechanisms, resolve_slot
    from mechanism_ids import choose_sign_mechanism
    lib = PyKCS11.PyKCS11Lib()
    try:
        lib.load(module)
    except Exception as e:
        rep.add(FAIL, f"PyKCS11 не завантажив модуль: {e}")
        return
    try:
        try:
            slot = resolve_slot(lib, profile.slot, "token")
        except RuntimeError:
            rep.add(FAIL, "токен не видно (getSlotList(tokenPresent=True) порожній)")
            return
        try:
            info = lib.getTokenInfo(slot)
            rep.add(OK, f"токен: slot {slot}, label={info.label.strip()!r}, "
                        f"model={info.model.strip()!r}, fw={info.firmwareVersion[0]}.{info.firmwareVersion[1]}")
        except Exception as e:
            rep.add(FAIL, f"getTokenInfo(slot {slot}): {e}")
            return
        signing = [m for m, _n, i in iter_mechanisms(lib, PyKCS11, slot) if int(i.flags) & PyKCS11.CKF_SIGN]
        try:
            mech = int(profile.mechanism, 16) if profile.mechanism else choose_sign_mechanism(signing)
            rep.add(OK, f"механізм підпису: 0x{mech:08X}" + (" (зафіксовано в конфігу)" if profile.mechanism
                                                              else " (зі списку токена)"))
            if profile.mechanism and mech not in signing:
                rep.add(FAIL, f"зафіксований механізм 0x{mech:08X} токен не підтримує для підпису")
        except ValueError as e:
            rep.add(FAIL, f"механізм підпису не визначено: {e}")
        # Certificates are public objects: a session without C_Login sees them.
        session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
        try:
            certs = []
            for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
                cid = session.getAttributeValue(obj, [PyKCS11.CKA_ID])[0]
                if cid:
                    certs.append(bytes(cid).hex())
        finally:
            try:
                session.closeSession()
            except Exception:
                pass
        _report_certs(profile, certs, rep)
    finally:
        unload = getattr(lib, "unload", None)
        if unload:
            try:
                unload()
            except Exception:
                pass


def _check_agent(profile, sedo_url: str, rep: Report) -> None:
    from iit_client import IITClient, IITError, discover_agent
    found = discover_agent()
    if not found:
        rep.add(FAIL, "агент ІІТ (EUSignAgent) не відповідає на жодному відомому порту — "
                      "запущений «Користувач ЦСК»?")
        return
    host, port, https = found
    try:
        client = IITClient(host=host, port=port, use_https=https, origin=sedo_url)
        try:
            version = client.get_version()
        finally:
            client.close()
        rep.add(OK, f"агент: {'https' if https else 'http'}://{host}:{port}, версія {version}")
    except IITError as e:
        rep.add(FAIL, f"агент знайдено на {host}:{port}, але GetVersion не вдався: {e}")
    rep.add(WARN, f"cert_index = {profile.cert_index or 0}: перевіряється лише після ReadPrivateKey (з PIN)")


def check_profile(profile, sedo_url: str, is_auth_key: bool, rep: Report) -> None:
    rep.add("", f"[{profile.name}] backend {profile.backend}")
    backend = profile.backend
    if backend == "iit_agent":
        _check_agent(profile, sedo_url, rep)
    else:
        module, how = _module_for(profile)
        if not module:
            rep.add(FAIL, "модуль PKCS#11 не знайдено: задайте module у config_local.toml, "
                          "$SEDO_MODULE або $SEDO_MODULE_DIRS")
        elif not Path(module).is_file():
            rep.add(FAIL, f"модуль не існує: {module} ({how})")
            module = None
        else:
            rep.add(OK, f"модуль: {module} ({_bits(module)}, {how})")
        if module:
            if backend == "auto":
                import importlib.util
                has_pykcs11 = importlib.util.find_spec("PyKCS11") is not None
                from opensc_signer import OpenSCNotFound, OpenSCSigner
                try:
                    OpenSCSigner._find_tool()
                    backend = "opensc"
                except OpenSCNotFound:
                    backend = "pkcs11" if has_pykcs11 else "iit_agent"
                rep.add(OK, f"auto → буде використано {backend}")
            if backend == "opensc":
                _check_opensc(profile, module, rep)
            elif backend in ("pkcs11", "virtual"):
                if backend == "virtual":
                    key = profile.key_file
                    if key and not Path(key).is_file():
                        rep.add(FAIL, f"key_file не існує: {key}")
                    elif key:
                        rep.add(OK, f"key_file: {key}")
                _check_pykcs11(profile, module, rep)
            elif backend == "iit_agent":
                _check_agent(profile, sedo_url, rep)
    rep.add(*_pin_source(profile, is_auth_key))


def run_checks(config) -> Report:
    from sedo_config import ROLES
    rep = Report()
    rep.add("", "Конфігурація: " + (", ".join(str(s) for s in config.sources) or "жодного файлу (типові значення)"))
    rep.add("", "Ролі: " + ", ".join(f"{r} → {config.roles[r]}" for r in ROLES if r in config.roles))
    rep.add("", f"Python: {sys.version.split()[0]} {python_bitness()}-bit, {sys.platform}")
    auth_name = config.roles.get("auth")
    for profile in config.distinct_profiles():
        try:
            check_profile(profile, config.sedo_url, profile.name == auth_name, rep)
        except Exception as e:  # a check must never abort the whole report
            rep.add(FAIL, f"перевірка профілю впала: {type(e).__name__}: {e}")
    rep.add("", "Результат: " + ("OK" if rep.ok else f"{rep.problems} проблем(и), див. ✗ / ! вище"))
    return rep
