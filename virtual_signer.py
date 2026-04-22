"""
Virtual token signer via PKCS11.Virtual.EKeyAlmaz1C.dll.

Uses a software Key-6.dat file instead of a physical USB token.
Ideal for Linux/Wine deployment without hardware.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.26
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class VirtualTokenNotAvailable(Exception):
    """PyKCS11 or virtual PKCS#11 module not found."""


class VirtualSigner:
    """
    Signer backed by PKCS11.Virtual.EKeyAlmaz1C.dll + Key-6.dat.

    The virtual module reads Key-N.dat files (slot pattern Key-%X.dat,
    Key-6.dat = first slot) and provides the same PKCS#11 C_* API
    as the HW module, but without USB/SmartCard.

    All 68 C_* functions are implemented (no stubs), including
    Encrypt/Decrypt/GenerateKey that are stubs on HW.
    """

    DEFAULT_VIRTUAL_PATHS = [
        r"C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\PKCS11.Virtual.EKeyAlmaz1C.dll",
        r"C:\Program Files (x86)\Institute of Informational Technologies\Користувач ЦСК\PKCS11.Virtual.EKeyAlmaz1C.dll",
        r"C:\Program Files\Institute of Informational Technologies\PKCS11.Virtual.EKeyAlmaz1C.dll",
        "./PKCS11.Virtual.EKeyAlmaz1C.dll",
        "./libs/PKCS11.Virtual.EKeyAlmaz1C.dll",
    ]

    def __init__(self, module_path: Optional[str] = None,
                 key_file: Optional[str] = None):
        try:
            import PyKCS11
        except ImportError:
            raise VirtualTokenNotAvailable(
                "PyKCS11 not installed. Install: pip install PyKCS11"
            )

        self._pkcs11 = PyKCS11.PyKCS11Lib()
        self._PyKCS11 = PyKCS11
        self._session = None
        self._priv_key = None
        self._sign_mechanism = None

        if module_path is None:
            module_path = self._find_module()
        if not Path(module_path).exists():
            raise FileNotFoundError(
                f"Virtual PKCS#11 module not found: {module_path}"
            )

        if key_file and not Path(key_file).exists():
            raise FileNotFoundError(f"Key file not found: {key_file}")

        self.module_path = module_path
        self.key_file = key_file

        log.info("Loading Virtual PKCS#11 module: %s", module_path)
        self._pkcs11.load(module_path)
        info = self._pkcs11.getInfo()
        log.info("Library: %s v%d.%d",
                 info.libraryDescription.strip(),
                 info.libraryVersion[0], info.libraryVersion[1])

    @classmethod
    def _find_module(cls) -> str:
        for path in cls.DEFAULT_VIRTUAL_PATHS:
            if Path(path).exists():
                return path
        raise FileNotFoundError(
            f"PKCS11.Virtual.EKeyAlmaz1C.dll not found. "
            f"Checked: {cls.DEFAULT_VIRTUAL_PATHS}"
        )

    def _find_sign_mechanism(self) -> int:
        """Find DSTU 4145 signing mechanism (vendor-defined, >= 0x80000000)."""
        slots = self._pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("No virtual token slot")
        slot = slots[0]

        mech_types = self._pkcs11.getMechanismList(slot)
        for mt in mech_types:
            mech_id = int(mt)
            if mech_id < 0x80000000:
                continue
            info = self._pkcs11.getMechanismInfo(slot, mech_id)
            if int(info.flags) & self._PyKCS11.CKF_SIGN:
                log.info("Selected sign mechanism: 0x%08X", mech_id)
                return mech_id

        raise RuntimeError("No vendor signing mechanism found on virtual token")

    def login(self, pin: str, slot: Optional[int] = None) -> None:
        from pkcs11_signer import check_almaz_mutex
        held = check_almaz_mutex()
        if held:
            log.warning(
                "Another IIT session holds mutex %s. "
                "HW and Virtual modules share the same mutex — "
                "concurrent access will fail.", held
            )

        if slot is None:
            slots = self._pkcs11.getSlotList(tokenPresent=True)
            if not slots:
                raise RuntimeError("No virtual token slot available")
            slot = slots[0]

        flags = self._PyKCS11.CKF_RW_SESSION | self._PyKCS11.CKF_SERIAL_SESSION
        self._session = self._pkcs11.openSession(slot, flags)
        self._session.login(pin)

        keys = self._session.findObjects([
            (self._PyKCS11.CKA_CLASS, self._PyKCS11.CKO_PRIVATE_KEY)
        ])
        if not keys:
            raise RuntimeError("No private keys in virtual token")
        self._priv_key = keys[0]

        if self._sign_mechanism is None:
            self._sign_mechanism = self._find_sign_mechanism()

        log.info("Virtual token logged in, mechanism=0x%08X",
                 self._sign_mechanism)

    def get_certificate(self) -> bytes:
        if not self._session:
            raise RuntimeError("Not logged in")
        certs = self._session.findObjects([
            (self._PyKCS11.CKA_CLASS, self._PyKCS11.CKO_CERTIFICATE)
        ])
        if not certs:
            raise RuntimeError("No certificates in virtual token")
        attrs = self._session.getAttributeValue(
            certs[0], [self._PyKCS11.CKA_VALUE]
        )
        return bytes(attrs[0])

    def sign(self, data: bytes, mechanism: Optional[int] = None) -> bytes:
        if not self._session or not self._priv_key:
            raise RuntimeError("Not logged in")
        if mechanism is None:
            mechanism = self._sign_mechanism
        if mechanism is None:
            raise RuntimeError("No sign mechanism discovered")

        mech = self._PyKCS11.Mechanism(mechanism, None)
        signature = self._session.sign(self._priv_key, data, mech)
        return bytes(signature)

    def logout(self) -> None:
        if self._session:
            try:
                self._session.logout()
            except Exception:
                pass
            try:
                self._session.closeSession()
            except Exception:
                pass
            self._session = None
            self._priv_key = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.logout()
