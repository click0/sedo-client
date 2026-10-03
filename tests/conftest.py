"""Pytest shared config — додає корінь проекту у sys.path для імпортів."""
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def fake_pykcs11(monkeypatch):
    """
    Install a fake ``PyKCS11`` module into ``sys.modules``.

    PyKCS11 is absent in CI (tests.yml installs only requests+pytest), so this
    is the only way to exercise the bodies of ``virtual_signer`` /
    ``pkcs11_signer``. Tests configure the token via ``mod.MECHS`` (mechanism
    id → flags) before constructing a signer.
    """
    mod = types.ModuleType("PyKCS11")

    # PKCS#11 constants used by the signers.
    mod.CKF_SIGN = 0x800
    mod.CKF_VERIFY = 0x2000
    mod.CKF_RW_SESSION = 0x2
    mod.CKF_SERIAL_SESSION = 0x4
    mod.CKA_CLASS = 0x0
    mod.CKA_VALUE = 0x11
    mod.CKA_ID = 0x102
    mod.CKO_CERTIFICATE = 0x1
    mod.CKO_PRIVATE_KEY = 0x3

    # Token surface configurable per test: {mechanism_id: flags}.
    mod.MECHS = {}
    # Per-slot override of MECHS: {slot: {mechanism_id: flags}}.
    mod.MECHS_BY_SLOT = {}
    mod.SLOTS = [0]
    mod.CERT_DER = b"\x30\x82\x01\x00" + b"\x00" * 16
    mod.SIGNATURE = b"\x00" * 64

    # Objects on the token. Defaults: one private key and one certificate,
    # linked by the same CKA_ID — a freshly issued Almaz-1K. Tests that need a
    # multi-pair token replace these lists and fill OBJ_ATTRS.
    mod.PRIVATE_KEYS = [object()]
    mod.CERTS = [object()]
    # {obj: {attribute: value}}; missing entries fall back to CKA_ID b"\x01"
    # and CKA_VALUE CERT_DER.
    mod.OBJ_ATTRS = {}

    # Session bookkeeping so tests can prove handles are closed.
    mod.BROKEN_MECHS = set()   # ids whose getMechanismInfo raises PyKCS11Error
    mod.SESSIONS = []          # every session ever opened, in order
    mod.LOGIN_ERROR = None     # exception instance raised by Session.login
    mod.SIGN_CALLS = []        # (key, mechanism id) per Session.sign
    mod.UNLOADS = []           # module path per PyKCS11Lib.unload
    mod.GETINFO_ERROR = None   # exception instance raised by getInfo

    class PyKCS11Error(Exception):
        """Stand-in for PyKCS11.PyKCS11Error (CKR_* failures)."""

    mod.PyKCS11Error = PyKCS11Error

    class Mechanism:
        def __init__(self, mech_type, param=None):
            self.mechType = mech_type
            self.param = param

    class _Info:
        def __init__(self, flags):
            self.flags = flags
            self.ulMinKeySize = 163
            self.ulMaxKeySize = 509

    class _LibInfo:
        libraryDescription = "Fake PKCS#11 Library"
        libraryVersion = (1, 0)
        manufacturerID = "fake"

    class _TokenInfo:
        label = "FakeToken"
        manufacturerID = "fake"
        model = "fake"
        serialNumber = "0000"
        firmwareVersion = (1, 0)

    class _Session:
        def __init__(self, slot):
            self.slot = slot
            self.logged_in = False
            self.closed = False

        def login(self, pin):
            if mod.LOGIN_ERROR is not None:
                raise mod.LOGIN_ERROR
            self.logged_in = True

        def logout(self):
            self.logged_in = False

        def closeSession(self):
            self.closed = True

        def findObjects(self, template):
            cls = dict(template).get(mod.CKA_CLASS)
            if cls == mod.CKO_PRIVATE_KEY:
                return list(mod.PRIVATE_KEYS)
            if cls == mod.CKO_CERTIFICATE:
                return list(mod.CERTS)
            return []

        def getAttributeValue(self, obj, attrs):
            own = mod.OBJ_ATTRS.get(obj, {})
            out = []
            for attr in attrs:
                if attr in own:
                    out.append(own[attr])
                elif attr == mod.CKA_ID:
                    out.append(b"\x01")
                elif attr == mod.CKA_VALUE:
                    out.append(mod.CERT_DER)
                else:
                    out.append(None)
            return out

        def sign(self, key, data, mech):
            mod.SIGN_CALLS.append((key, mech.mechType))
            return mod.SIGNATURE

    _STD_NAMES = {0x1041: "CKM_ECDSA", 0x1042: "CKM_ECDSA_SHA1", 0x1: "CKM_RSA_PKCS",
                  0x250: "CKM_SHA256", 0x108A: "CKM_AES_CMAC"}
    mod.CKM = {}

    def _mech_name(mech_id):
        name = mod.CKM.get(mech_id)
        if name is None:
            if mech_id in _STD_NAMES:
                name = _STD_NAMES[mech_id]
            elif mech_id >= 0x80000000:
                name = f"CKM_VENDOR_DEFINED_0x{mech_id - 0x80000000:X}"
            else:
                name = f"CKM_UNKNOWN_0x{mech_id:X}"
            mod.CKM[name] = mech_id
            mod.CKM[mech_id] = name
        return name

    class PyKCS11Lib:
        def __init__(self):
            self.loaded = None

        def load(self, path):
            self.loaded = path

        def unload(self):
            mod.UNLOADS.append(self.loaded)
            self.loaded = None

        def getInfo(self):
            if mod.GETINFO_ERROR is not None:
                raise mod.GETINFO_ERROR
            return _LibInfo()

        def getSlotList(self, tokenPresent=False):
            return list(mod.SLOTS)

        def getTokenInfo(self, slot):
            return _TokenInfo()

        def getMechanismList(self, slot):
            # Like the real library: a list of CKM_* NAMES, registered in CKM
            # both ways; vendor ids as CKM_VENDOR_DEFINED_0x<id-0x80000000>.
            return [_mech_name(m) for m in mod.MECHS_BY_SLOT.get(slot, mod.MECHS)]

        def getMechanismInfo(self, slot, mech):
            # Real PyKCS11 does CKM[mech] and passes the result to C: a name
            # maps to its int and works, an int maps to its NAME and the C
            # layer raises TypeError. Mirror that so int(mt)-style code fails
            # here as it does on a real token.
            if not isinstance(mech, str):
                raise TypeError("in method 'CPKCS11Lib_C_GetMechanismInfo', "
                                "argument 3 of type 'unsigned long'")
            mech_id = mod.CKM[mech]
            if mech_id in mod.BROKEN_MECHS:
                raise mod.PyKCS11Error("CKR_MECHANISM_INVALID (0x00000070)")
            return _Info(mod.MECHS_BY_SLOT.get(slot, mod.MECHS).get(mech_id, 0))

        def openSession(self, slot, flags):
            session = _Session(slot)
            mod.SESSIONS.append(session)
            return session

    mod.Mechanism = Mechanism
    mod.PyKCS11Lib = PyKCS11Lib

    monkeypatch.setitem(sys.modules, "PyKCS11", mod)
    return mod
