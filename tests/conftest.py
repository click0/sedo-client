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
    mod.CKO_CERTIFICATE = 0x1
    mod.CKO_PRIVATE_KEY = 0x3

    # Token surface configurable per test: {mechanism_id: flags}.
    mod.MECHS = {}
    mod.PRIVATE_KEYS = [object()]
    mod.CERT_DER = b"\x30\x82\x01\x00" + b"\x00" * 16
    mod.SIGNATURE = b"\x00" * 64

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
        def __init__(self):
            self.logged_in = False
            self.closed = False

        def login(self, pin):
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
                return [object()]
            return []

        def getAttributeValue(self, obj, attrs):
            return [mod.CERT_DER]

        def sign(self, key, data, mech):
            return mod.SIGNATURE

    class PyKCS11Lib:
        def __init__(self):
            self.loaded = None

        def load(self, path):
            self.loaded = path

        def getInfo(self):
            return _LibInfo()

        def getSlotList(self, tokenPresent=False):
            return [0]

        def getTokenInfo(self, slot):
            return _TokenInfo()

        def getMechanismList(self, slot):
            return list(mod.MECHS.keys())

        def getMechanismInfo(self, slot, mech_id):
            return _Info(mod.MECHS.get(mech_id, 0))

        def openSession(self, slot, flags):
            return _Session()

    mod.Mechanism = Mechanism
    mod.PyKCS11Lib = PyKCS11Lib

    monkeypatch.setitem(sys.modules, "PyKCS11", mod)
    return mod
