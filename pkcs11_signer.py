"""
Прямий PKCS#11 клієнт для PKCS11.EKeyAlmaz1C.dll через PyKCS11.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.26
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import logging
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# Mutex-и які створює PKCS11.EKeyAlmaz1C.dll (ADDENDUM v1, v2).
# HW та Virtual модулі тримають ті самі mutex-и — одночасний запуск конфліктує.
ALMAZ_MUTEX_NAMES = [
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

# IIT vendor-defined mechanisms (не встановлено в PKCS#11 стандарт)
# Виявляються runtime. Ці імена — евристичні назви що ми присвоюємо.
# Справжні ID визначає C_GetMechanismList.
MECH_NAME_HINTS = {
    # IIT / UA-specific mechanism name hints (якщо ID >= 0x80000000)
    "DSTU4145": ["dstu", "4145", "uac", "gf2m"],
    "DSTU7564": ["7564", "kupyna", "hash"],
    "DSTU7624": ["7624", "kalyna", "cipher"],
    "GOST34311": ["34311", "gost hash"],
    "GOST28147": ["28147", "gost cipher"],
}


class PKCS11Signer:
    """
    Прямий PKCS#11 клієнт через PKCS11_EKeyAlmaz1C.dll.

    Mechanism ID для підпису auto-discovered при першому виклику.
    """

    DEFAULT_MODULE_PATHS = [
        # Підтверджений інсталером IIT шлях — див. README.md / opensc-test-almaz.ps1
        r"C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\PKCS11.EKeyAlmaz1C.dll",
        r"C:\Program Files (x86)\Institute of Informational Technologies\ЄвроЗнак\PKCS11_EKeyAlmaz1C.dll",
        r"C:\Program Files (x86)\Institute of Informational Technologies\Користувач ЦСК\PKCS11_EKeyAlmaz1C.dll",
        r"C:\Program Files\Institute of Informational Technologies\PKCS11_EKeyAlmaz1C.dll",
        "./PKCS11_EKeyAlmaz1C.dll",
        "./libs/PKCS11_EKeyAlmaz1C.dll",
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
        self._sign_mechanism = None  # lazy discovered

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
            f"PKCS11_EKeyAlmaz1C.dll не знайдено. "
            f"Перевір: {cls.DEFAULT_MODULE_PATHS}"
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

    def find_sign_mechanism(self, prefer_dstu: bool = True) -> int:
        """
        Знаходить правильний mechanism ID для підпису.
        Евристика: шукаємо перший mechanism з CKF_SIGN flag.
        Якщо prefer_dstu=True, пріоритет на vendor-defined (>= 0x80000000).

        Повертає numeric mechanism ID.
        """
        mechanisms = self.list_mechanisms()
        signing = [m for m in mechanisms if m["can_sign"]]
        if not signing:
            raise RuntimeError("No signing mechanism supported")

        log.info("Available signing mechanisms:")
        for m in signing:
            log.info("  %s  min=%d max=%d", m["hex"], m["min_key"], m["max_key"])

        # Фільтр: DSTU/vendor mechanisms мають ID >= 0x80000000
        # Для Алмаза — майже напевно DSTU 4145
        if prefer_dstu:
            vendor = [m for m in signing if m["id"] >= 0x80000000]
            if vendor:
                mech = vendor[0]
                log.info("Selected vendor mechanism: %s", mech["hex"])
                return mech["id"]

        # Fallback — перший що вміє sign
        mech = signing[0]
        log.info("Selected mechanism: %s", mech["hex"])
        return mech["id"]

    # ─── Session ─────────────────────────────────────────────

    def login(self, pin: str, slot: Optional[int] = None) -> None:
        held = check_almaz_mutex()
        if held:
            log.warning(
                "Another IIT session holds mutex %s. "
                "Concurrent access may fail or corrupt token state.", held
            )

        if slot is None:
            slots = self._pkcs11.getSlotList(tokenPresent=True)
            if not slots:
                raise RuntimeError("No token connected")
            slot = slots[0]

        flags = self._PyKCS11.CKF_RW_SESSION | self._PyKCS11.CKF_SERIAL_SESSION
        self._session = self._pkcs11.openSession(slot, flags)
        self._session.login(pin)

        keys = self._session.findObjects([
            (self._PyKCS11.CKA_CLASS, self._PyKCS11.CKO_PRIVATE_KEY)
        ])
        if not keys:
            raise RuntimeError("No private keys on token")
        self._priv_key = keys[0]

        # Auto-discover sign mechanism якщо не задано
        if self._sign_mechanism is None:
            try:
                self._sign_mechanism = self.find_sign_mechanism()
            except Exception as e:
                log.warning("Could not auto-discover mechanism: %s", e)

        log.info("Logged in, private key ready, mechanism=%s",
                 f"0x{self._sign_mechanism:08X}" if self._sign_mechanism else "?")

    def get_certificate(self) -> bytes:
        if not self._session:
            raise RuntimeError("Not logged in")
        certs = self._session.findObjects([
            (self._PyKCS11.CKA_CLASS, self._PyKCS11.CKO_CERTIFICATE)
        ])
        if not certs:
            raise RuntimeError("No certificates")
        attrs = self._session.getAttributeValue(certs[0], [self._PyKCS11.CKA_VALUE])
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
            try: self._session.logout()
            except Exception: pass
            try: self._session.closeSession()
            except Exception: pass
            self._session = None
            self._priv_key = None

    def __enter__(self): return self
    def __exit__(self, *args): self.logout()


# ═══════════════════════════════════════════════════════════════
# CLI — discovery + testing
# ═══════════════════════════════════════════════════════════════

def main():
    import argparse, sys

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

        # Підказка
        signing = [m for m in mechs if m["can_sign"]]
        vendor_signing = [m for m in signing if m['id'] >= 0x80000000]
        print()
        if vendor_signing:
            print(f"⚑ Рекомендований sign mechanism: {vendor_signing[0]['hex']}")
            print(f"  (vendor-defined, ймовірно DSTU 4145)")

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
