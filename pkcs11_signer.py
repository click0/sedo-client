"""
Прямий PKCS#11 клієнт для PKCS11.EKeyAlmaz1C.dll через PyKCS11.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import logging
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

__all__ = ["PKCS11Signer", "PKCS11NotAvailable", "check_almaz_mutex"]

# Mutex-и які створює PKCS11.EKeyAlmaz1C.dll (ADDENDUM v1, v2).
# HW та Virtual модулі тримають ті самі mutex-и — одночасний запуск конфліктує.
ALMAZ_MUTEX_NAMES = [
    "Global\\EKAlmaz1COpenMutex",
    "Global\\EKAlmaz1CMutex",
    "Global\\EKAlmaz1CMemory",
]


def check_almaz_mutex() -> Optional[str]:
    """
    Check whether another IIT session already holds the Almaz-1K mutex.

    Returns the name of the held mutex, or None if free.
    Only works on Windows; returns None on other platforms.
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        OpenMutexW = kernel32.OpenMutexW
        OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
        OpenMutexW.restype = wintypes.HANDLE
        CloseHandle = kernel32.CloseHandle

        SYNCHRONIZE = 0x00100000
        for name in ALMAZ_MUTEX_NAMES:
            handle = OpenMutexW(SYNCHRONIZE, False, name)
            if handle:
                CloseHandle(handle)
                return name
    except Exception as e:
        log.debug("Mutex check failed: %s", e)
    return None


# ═══════════════════════════════════════════════════════════════
# Session helpers shared by PKCS11Signer and VirtualSigner
# ═══════════════════════════════════════════════════════════════

def resolve_slot(lib, slot: Optional[int], what: str) -> int:
    """The explicit slot, or the first slot with a token present."""
    if slot is not None:
        return slot
    slots = lib.getSlotList(tokenPresent=True)
    if not slots:
        raise RuntimeError(f"No {what}")
    return slots[0]


def close_session(session) -> None:
    """Best-effort C_Logout + C_CloseSession; never raises."""
    try:
        session.logout()
    except Exception as e:
        log.debug("Session logout error (ignored): %s", e)
    try:
        session.closeSession()
    except Exception as e:
        log.debug("Session close error (ignored): %s", e)


def _object_id(session, P, obj) -> Optional[bytes]:
    try:
        value = session.getAttributeValue(obj, [P.CKA_ID])[0]
    except Exception:
        return None
    return bytes(value) if value else None


def select_key_and_cert(session, P):
    """
    Pick the private key and THE certificate that belongs to it.

    PKCS#11 links a key to its certificate through an equal CKA_ID. Taking
    keys[0] and certs[0] independently — as both signers used to — breaks on
    any token that holds more than one pair (routine for MoD-issued keys: a
    KEP signing cert plus an encryption/TLS cert). The client then sent the
    server one certificate and a signature made by a different key; the
    server rejected it and every local log still said "✓ Certificate".

    Returns (key, cert) where cert may be None when the token has none.
    Falls back to the first of each — the historical behaviour — only when no
    CKA_ID pair exists, and warns if that choice is actually ambiguous.
    """
    keys = session.findObjects([(P.CKA_CLASS, P.CKO_PRIVATE_KEY)])
    if not keys:
        return None, None
    certs = session.findObjects([(P.CKA_CLASS, P.CKO_CERTIFICATE)])

    cert_by_id = {}
    for cert in certs:
        cid = _object_id(session, P, cert)
        if cid is not None:
            cert_by_id.setdefault(cid, cert)
    for key in keys:
        kid = _object_id(session, P, key)
        if kid is not None and kid in cert_by_id:
            return key, cert_by_id[kid]

    if len(keys) > 1 or len(certs) > 1:
        log.warning(
            "Could not match a certificate to a private key by CKA_ID "
            "(%d keys, %d certificates); using the first of each — the "
            "certificate may not belong to the signing key", len(keys), len(certs))
    return keys[0], (certs[0] if certs else None)


def open_logged_in_session(lib, P, slot: int, pin: str):
    """
    C_OpenSession + C_Login, closing the session if anything after the open
    fails. Previously a wrong PIN left an open, un-logged-in session behind,
    and each retry leaked another handle — on an Almaz-1K with a small
    session limit a few retries end in CKR_SESSION_COUNT.
    """
    session = lib.openSession(slot, P.CKF_RW_SESSION | P.CKF_SERIAL_SESSION)
    try:
        session.login(pin)
    except Exception:
        close_session(session)
        raise
    return session


class PKCS11NotAvailable(Exception):
    """PyKCS11 не встановлено або модуль не знайдено."""


# Стандартні PKCS#11 mechanisms (для identification)
CKM_STANDARD = {
    0x00000002: "CKM_RSA_PKCS",
    0x00000001: "CKM_RSA_PKCS_KEY_PAIR_GEN",
    0x00000220: "CKM_SHA_1",
    0x00000250: "CKM_SHA256",
    0x00001041: "CKM_EC_KEY_PAIR_GEN",
    0x00001042: "CKM_ECDSA",
    0x00001043: "CKM_ECDSA_SHA1",
}

class PKCS11Signer:
    """
    Прямий PKCS#11 клієнт для DSTU 4145 токенів.

    Підтримує:
    - IIT Алмаз-1К (PKCS11.EKeyAlmaz1C.dll), mechanism 0x80420031
    - Avest CC-337 / SecureToken-338 (Av337CryptokiD.dll), mechanism 0x00000352
    - Avest AvestKey / EfitKey (avcryptokinxt.dll)

    Mechanism ID для підпису auto-discovered при першому виклику login().
    """

    DEFAULT_MODULE_PATHS = [
        # ─ IIT Алмаз-1К (підтверджений інсталером шлях) ─
        r"C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\PKCS11.EKeyAlmaz1C.dll",
        r"C:\Program Files (x86)\Institute of Informational Technologies\ЄвроЗнак\PKCS11_EKeyAlmaz1C.dll",
        r"C:\Program Files (x86)\Institute of Informational Technologies\Користувач ЦСК\PKCS11_EKeyAlmaz1C.dll",
        r"C:\Program Files\Institute of Informational Technologies\PKCS11_EKeyAlmaz1C.dll",
        # ─ Avest CC-337 / SecureToken-338 (Av337CryptokiD.dll) ─
        r"C:\Program Files (x86)\Avest\AvestKey\Av337CryptokiD.dll",
        r"C:\Program Files (x86)\Avest\Av337CryptokiD.dll",
        r"C:\Windows\SysWOW64\Av337CryptokiD.dll",
        # ─ Avest AvestKey / EfitKey / AvPassG (avcryptokinxt.dll) ─
        r"C:\Program Files (x86)\Avest\AvestKey\avcryptokinxt.dll",
        r"C:\Windows\SysWOW64\avcryptokinxt.dll",
        # ─ локальні ─
        "./PKCS11_EKeyAlmaz1C.dll",
        "./libs/PKCS11_EKeyAlmaz1C.dll",
        "./Av337CryptokiD.dll",
        "./libs/Av337CryptokiD.dll",
    ]

    def __init__(self, module_path: Optional[str] = None):
        try:
            import PyKCS11
        except ImportError:
            raise PKCS11NotAvailable(
                "PyKCS11 не встановлено. Встанови: pip install PyKCS11"
            )

        self._pkcs11 = PyKCS11.PyKCS11Lib()
        self._PyKCS11 = PyKCS11
        self._session = None
        self._priv_key = None
        self._cert_obj = None
        self._slot = None
        self._sign_mechanism = None  # lazy discovered, per slot

        if module_path is None:
            module_path = self._find_module()
        if not Path(module_path).exists():
            raise FileNotFoundError(f"PKCS11 module not found: {module_path}")

        self.module_path = module_path
        log.info("Loading PKCS#11 module: %s", module_path)
        self._pkcs11.load(module_path)
        info = self._pkcs11.getInfo()
        log.info("Library: %s v%d.%d, Manufacturer: %s",
                 info.libraryDescription.strip(),
                 info.libraryVersion[0], info.libraryVersion[1],
                 info.manufacturerID.strip())

    @classmethod
    def _find_module(cls) -> str:
        for path in cls.DEFAULT_MODULE_PATHS:
            if Path(path).exists():
                return path
        raise FileNotFoundError(
            f"PKCS#11 module not found (IIT PKCS11.EKeyAlmaz1C.dll or "
            f"Avest Av337CryptokiD.dll). Pass --module explicitly or place "
            f"the DLL in one of: {cls.DEFAULT_MODULE_PATHS}"
        )

    # ─── Discovery ───────────────────────────────────────────

    def list_slots(self) -> list[dict]:
        slots = self._pkcs11.getSlotList(tokenPresent=True)
        result = []
        for slot in slots:
            info = self._pkcs11.getTokenInfo(slot)
            result.append({
                "slot_id": slot,
                "label": info.label.strip(),
                "manufacturer": info.manufacturerID.strip(),
                "model": info.model.strip(),
                "serial": info.serialNumber.strip(),
                "firmware": f"{info.firmwareVersion[0]}.{info.firmwareVersion[1]}",
            })
        return result

    def list_mechanisms(self, slot: Optional[int] = None) -> list[dict]:
        """
        Повертає список mechanisms токена.
        Викликається для discovery правильних sign mechanism ID.
        """
        if slot is None:
            slots = self._pkcs11.getSlotList(tokenPresent=True)
            if not slots:
                raise RuntimeError("No token")
            slot = slots[0]

        mech_types = self._pkcs11.getMechanismList(slot)
        result = []
        for mt in mech_types:
            # mt — числовий ID
            mech_id = int(mt)
            info = self._pkcs11.getMechanismInfo(slot, mech_id)
            name = CKM_STANDARD.get(mech_id, f"CKM_VENDOR_0x{mech_id:08X}")
            # Перевірити чи має Sign flag
            flags = int(info.flags)
            can_sign = bool(flags & self._PyKCS11.CKF_SIGN)
            result.append({
                "id": mech_id,
                "name": name,
                "hex": f"0x{mech_id:08X}",
                "min_key": int(info.ulMinKeySize),
                "max_key": int(info.ulMaxKeySize),
                "flags": flags,
                "can_sign": can_sign,
                "can_verify": bool(flags & self._PyKCS11.CKF_VERIFY),
            })
        return result

    def find_sign_mechanism(self, prefer_dstu: bool = True,
                            slot: Optional[int] = None) -> int:
        """
        Знаходить правильний mechanism ID для підпису.

        Порядок:
        1. Відомий DSTU 4145 ID з реєстру (IIT 0x80420031/32 або
           Avest/стандарт 0x00000352) — найнадійніше для обох вендорів.
        2. Будь-який vendor-defined (>= 0x80000000) — для нових IIT-токенів.
        3. Перший mechanism з CKF_SIGN — останній fallback.

        Повертає numeric mechanism ID.
        """
        from mechanism_ids import choose_sign_mechanism

        # The slot we are logged into, not slots[0]: with two tokens present,
        # login(pin, slot=1) used to discover mechanisms on slot 0 and then
        # C_SignInit an IIT vendor mechanism on, say, an Avest token.
        mechanisms = self.list_mechanisms(slot if slot is not None else self._slot)
        signing = [m for m in mechanisms if m["can_sign"]]
        if not signing:
            raise RuntimeError("No signing mechanism supported")

        log.info("Available signing mechanisms:")
        for m in signing:
            log.info("  %s  min=%d max=%d", m["hex"], m["min_key"], m["max_key"])

        if not prefer_dstu:
            mech = signing[0]["id"]
        else:
            # Shared 3-tier policy (known DSTU → vendor → first) — the same
            # helper VirtualSigner uses, so both backends behave identically.
            try:
                mech = choose_sign_mechanism(m["id"] for m in signing)
            except ValueError as e:
                # Only non-signature mechanisms (e.g. SYM_MAC) on the token.
                raise RuntimeError(f"No DSTU 4145 signing mechanism: {e}") from e
        log.info("Selected sign mechanism: 0x%08X", mech)
        return mech

    # ─── Session ─────────────────────────────────────────────

    def login(self, pin: str, slot: Optional[int] = None) -> None:
        held = check_almaz_mutex()
        if held:
            log.warning(
                "Another IIT session holds mutex %s. "
                "Concurrent access may fail or corrupt token state.", held
            )

        # Re-login must not leak the previous session handle, and must not
        # leave a stale _priv_key pointing into a session we are replacing.
        if self._session is not None:
            self.logout()

        slot = resolve_slot(self._pkcs11, slot, "token connected")
        session = open_logged_in_session(self._pkcs11, self._PyKCS11, slot, pin)
        try:
            key, cert = select_key_and_cert(session, self._PyKCS11)
            if key is None:
                raise RuntimeError("No private keys on token")
            mech = self._sign_mechanism
            if mech is None or slot != self._slot:
                mech = self.find_sign_mechanism(slot=slot)
        except Exception:
            close_session(session)
            raise

        self._session, self._slot = session, slot
        self._priv_key, self._cert_obj = key, cert
        self._sign_mechanism = mech
        log.info("Logged in (slot %s), private key ready, mechanism=0x%08X",
                 slot, mech)

    def get_certificate(self) -> bytes:
        if not self._session:
            raise RuntimeError("Not logged in")
        if self._cert_obj is None:
            raise RuntimeError("No certificates")
        attrs = self._session.getAttributeValue(self._cert_obj, [self._PyKCS11.CKA_VALUE])
        return bytes(attrs[0])

    def sign(self, data: bytes, mechanism: Optional[int] = None) -> bytes:
        """Підписати дані знайденим (або явно заданим) mechanism."""
        if not self._session or not self._priv_key:
            raise RuntimeError("Not logged in")
        if mechanism is None:
            mechanism = self._sign_mechanism
        if mechanism is None:
            raise RuntimeError("No sign mechanism. Use find_sign_mechanism() first")

        mech = self._PyKCS11.Mechanism(mechanism, None)
        signature = self._session.sign(self._priv_key, data, mech)
        return bytes(signature)

    def logout(self) -> None:
        if self._session:
            close_session(self._session)
            self._session = None
            self._priv_key = None
            self._cert_obj = None

    def __enter__(self): return self
    def __exit__(self, *args):
        self.logout()
        return False


# ═══════════════════════════════════════════════════════════════
# CLI — discovery + testing
# ═══════════════════════════════════════════════════════════════

def main():
    import argparse
    from _console import force_utf8_io
    force_utf8_io()

    parser = argparse.ArgumentParser(
        description="PKCS#11 signer — для тестування PKCS11_EKeyAlmaz1C.dll"
    )
    parser.add_argument("--module", help="Шлях до PKCS11_EKeyAlmaz1C.dll")
    parser.add_argument("--list-slots", action="store_true", help="Показати слоти")
    parser.add_argument("--list-mechanisms", action="store_true",
                        help="Показати підтримувані mechanisms (КРИТИЧНЕ для налаштування!)")
    parser.add_argument("--pin", help="Token PIN")
    parser.add_argument("--sign", metavar="FILE", help="Підписати файл")
    parser.add_argument("--output", help="Вивід підпису")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        signer = PKCS11Signer(args.module)
    except (PKCS11NotAvailable, FileNotFoundError) as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)

    if args.list_slots:
        slots = signer.list_slots()
        print(f"\n{len(slots)} slot(s):")
        for s in slots:
            print(f"  [{s['slot_id']}] label={s['label']}")
            print(f"       manufacturer={s['manufacturer']}")
            print(f"       model={s['model']} serial={s['serial']}")
            print(f"       firmware={s['firmware']}")

    if args.list_mechanisms:
        mechs = signer.list_mechanisms()
        print(f"\n{len(mechs)} mechanism(s) supported by token:\n")
        print(f"  {'ID':<12} {'Name':<35} {'Sign':<5} {'Verify':<6} Min-Max keysize")
        print(f"  {'-'*12} {'-'*35} {'-'*5} {'-'*6} ---------------")
        for m in mechs:
            s = "✓" if m["can_sign"] else " "
            v = "✓" if m["can_verify"] else " "
            print(f"  {m['hex']:<12} {m['name']:<35}  {s}     {v}    "
                  f"{m['min_key']}-{m['max_key']}")

        # Підказка. Свідомо через choose_sign_mechanism, а не "перший
        # vendor-defined": на Алмазі перший vendor-defined із CKF_SIGN — це
        # 0x80420014 (SYM_MAC), і порада підписати ним спалює одну з 15
        # PIN-спроб. login() використовує саме цю політику, тож підказка
        # мусить збігатися з тим, що клієнт реально робить.
        from mechanism_ids import choose_sign_mechanism
        signing = [m for m in mechs if m["can_sign"]]
        print()
        try:
            rec = choose_sign_mechanism(m["id"] for m in signing)
        except ValueError as e:
            print(f"⚠ Немає механізму підпису ДСТУ 4145: {e}")
        else:
            print(f"⚑ Рекомендований sign mechanism: 0x{rec:08X}")
            print("  (та сама політика, що й у login(): відомий ДСТУ 4145 →"
                  " vendor-defined → перший)")

    if args.sign:
        if not args.pin:
            import getpass
            args.pin = getpass.getpass("PIN: ")

        data = Path(args.sign).read_bytes()
        with signer:
            signer.login(args.pin)
            cert = signer.get_certificate()
            print(f"✓ Certificate: {len(cert)} bytes")
            try:
                signature = signer.sign(data)
                print(f"✓ Signature: {len(signature)} bytes (mechanism 0x{signer._sign_mechanism:08X})")
            except Exception as e:
                print(f"❌ Sign failed: {e}", file=sys.stderr)
                print(f"   Try --list-mechanisms to see what's supported", file=sys.stderr)
                sys.exit(2)

        output = args.output or args.sign + ".sig"
        Path(output).write_bytes(signature)
        print(f"✓ Written: {output}")


if __name__ == "__main__":
    main()
