"""
Virtual token signer via PKCS11.Virtual.EKeyAlmaz1C.dll.

Uses a software Key-6.dat file instead of a physical USB token.
Ideal for Linux/Wine deployment without hardware.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

__all__ = ["VirtualSigner", "VirtualTokenNotAvailable"]


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
        str(Path.home() / "AppData" / "Roaming" / "Institute of Informational Technologies"
            / "EKeys" / "Almaz1C" / "PKCS11.Virtual.EKeyAlmaz1C.dll"),
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
        self._cert_obj = None
        self._slot = None
        self._sign_mechanism = None

        if module_path is None:
            module_path = self._find_module()
        if not Path(module_path).exists():
            raise FileNotFoundError(
                f"Virtual PKCS#11 module not found: {module_path}"
            )

        if key_file and not Path(key_file).exists():
            raise FileNotFoundError(f"Key file not found: {key_file}")

        # The virtual DLL does NOT take a key path: KM_FileSystem.dll resolves
        # "%sKey-%X.dat" from a directory configured in the registry
        # (...\Libraries\Sign\Path) / EUSetPrivateKeyMediaSettings — see
        # docs/IIT-ANALYSIS-ADDENDUM-v6.md §2.3.3. So --key-file can only be
        # validated here; warn loudly if it is not where the DLL will look.
        if key_file:
            key_dir = Path(key_file).resolve().parent
            mod_dir = Path(module_path).resolve().parent
            if key_dir != mod_dir:
                log.warning(
                    "--key-file %s is not next to the virtual module (%s). "
                    "The DLL loads Key-N.dat from its registry-configured "
                    "directory, not from this path — it may sign with a "
                    "different key. Place the file in the module directory "
                    "or set the registry Path accordingly.",
                    key_file, mod_dir,
                )

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

    def _find_sign_mechanism(self, slot: Optional[int] = None) -> int:
        """
        Find the DSTU 4145 signing mechanism on the virtual token.

        Prefers a known DSTU 4145 ID (IIT 0x80420031/32 or standard
        0x00000352), then any vendor-defined (>= 0x80000000) with CKF_SIGN.
        Uses the slot we logged into, not blindly slots[0].
        """
        from mechanism_ids import choose_sign_mechanism
        from pkcs11_signer import resolve_slot

        slot = resolve_slot(self._pkcs11, slot, "virtual token slot")

        # Same 3-tier policy as PKCS11Signer (known DSTU → vendor → first),
        # applied to the mechanisms that actually carry CKF_SIGN.
        signing = [
            int(mt) for mt in self._pkcs11.getMechanismList(slot)
            if int(self._pkcs11.getMechanismInfo(slot, int(mt)).flags)
            & self._PyKCS11.CKF_SIGN
        ]
        try:
            mech = choose_sign_mechanism(signing)
        except ValueError:
            raise RuntimeError("No signing mechanism found on virtual token")
        log.info("Selected sign mechanism: 0x%08X", mech)
        return mech

    def login(self, pin: str, slot: Optional[int] = None) -> None:
        from pkcs11_signer import (check_almaz_mutex, close_session,
                                   open_logged_in_session, resolve_slot,
                                   select_key_and_cert)
        held = check_almaz_mutex()
        if held:
            log.warning(
                "Another IIT session holds mutex %s. "
                "HW and Virtual modules share the same mutex — "
                "concurrent access will fail.", held
            )

        # Same lifecycle as PKCS11Signer: no leaked handle on re-login or on
        # a wrong PIN, certificate chosen by the signing key's CKA_ID, and the
        # mechanism discovered on the slot we actually logged into.
        if self._session is not None:
            self.logout()

        slot = resolve_slot(self._pkcs11, slot, "virtual token slot available")
        session = open_logged_in_session(self._pkcs11, self._PyKCS11, slot, pin)
        try:
            key, cert = select_key_and_cert(session, self._PyKCS11)
            if key is None:
                raise RuntimeError("No private keys in virtual token")
            mech = self._sign_mechanism
            if mech is None or slot != self._slot:
                mech = self._find_sign_mechanism(slot=slot)
        except Exception:
            close_session(session)
            raise

        self._session, self._slot = session, slot
        self._priv_key, self._cert_obj = key, cert
        self._sign_mechanism = mech
        log.info("Virtual token logged in (slot %s), mechanism=0x%08X", slot, mech)

    def get_certificate(self) -> bytes:
        if not self._session:
            raise RuntimeError("Not logged in")
        if self._cert_obj is None:
            raise RuntimeError("No certificates in virtual token")
        attrs = self._session.getAttributeValue(
            self._cert_obj, [self._PyKCS11.CKA_VALUE]
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
            from pkcs11_signer import close_session
            close_session(self._session)
            self._session = None
            self._priv_key = None
            self._cert_obj = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.logout()
        return False
