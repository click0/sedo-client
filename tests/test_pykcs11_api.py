"""
The real PyKCS11 API shape, as learnt from the SoftHSM run: getMechanismList
returns CKM_* names, getMechanismInfo takes a name, and PyKCS11 1.5.20 adds a
mechanism (0x1D) the token does not have. These run on the fake, which now
mirrors that behaviour.
"""

import pytest

from pkcs11_signer import iter_mechanisms, mechanism_id, signing_mechanism_ids


class TestMechanismId:
    @pytest.mark.parametrize("name,expected", [
        ("CKM_VENDOR_DEFINED_0x420031", 0x80420031),
        ("CKM_VENDOR_DEFINED_0x420014", 0x80420014),
        ("CKM_UNKNOWN_0x352", 0x352),
    ])
    def test_names_without_a_ckm_entry(self, name, expected):
        assert mechanism_id(type("P", (), {})(), name) == expected

    def test_known_name_via_ckm_dict(self):
        P = type("P", (), {"CKM": {"CKM_ECDSA": 0x1041}})()
        assert mechanism_id(P, "CKM_ECDSA") == 0x1041

    def test_int_passthrough(self):
        assert mechanism_id(type("P", (), {})(), 0x80420031) == 0x80420031

    def test_garbage_is_an_error(self):
        with pytest.raises(ValueError):
            mechanism_id(type("P", (), {})(), "CKM_WHATEVER")


class TestAgainstTheRealisticFake:
    def test_names_in_ids_out(self, fake_pykcs11):
        P = fake_pykcs11
        P.MECHS = {0x1041: P.CKF_SIGN, 0x80420031: P.CKF_SIGN, 0x80420014: P.CKF_SIGN,
                   0x250: 0}
        lib = P.PyKCS11Lib()
        assert P.PyKCS11Lib().getMechanismList(0) == [
            "CKM_ECDSA", "CKM_VENDOR_DEFINED_0x420031", "CKM_VENDOR_DEFINED_0x420014", "CKM_SHA256"]
        assert signing_mechanism_ids(lib, P, 0) == [0x1041, 0x80420031, 0x80420014]

    def test_int_to_get_mechanism_info_is_a_typeerror_like_the_real_library(self, fake_pykcs11):
        fake_pykcs11.MECHS = {0x1041: fake_pykcs11.CKF_SIGN}
        with pytest.raises(TypeError):
            fake_pykcs11.PyKCS11Lib().getMechanismInfo(0, 0x1041)

    def test_unqueryable_mechanism_is_skipped(self, fake_pykcs11):
        """PyKCS11 1.5.20 appends 0x1D to every list; its info is CKR_MECHANISM_INVALID."""
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN, 0x1D: P.CKF_SIGN}
        P.BROKEN_MECHS = {0x1D}
        ids = [m for m, _n, _i in iter_mechanisms(P.PyKCS11Lib(), P, 0)]
        assert ids == [0x80420031]

    def test_login_on_a_token_with_standard_mechanisms(self, fake_pykcs11, tmp_path):
        """The regression: int('CKM_RSA_PKCS') → ValueError at login()."""
        from pkcs11_signer import PKCS11Signer
        P = fake_pykcs11
        P.MECHS = {0x1: P.CKF_SIGN, 0x250: 0, 0x80420014: P.CKF_SIGN, 0x80420031: P.CKF_SIGN}
        dll = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        dll.write_bytes(b"x")
        s = PKCS11Signer(str(dll))
        s.login("1234")
        assert s._sign_mechanism == 0x80420031
        names = [m["name"] for m in s.list_mechanisms()]
        assert "CKM_RSA_PKCS" in names and "CKM_VENDOR_DEFINED_0x420031" in names

    def test_virtual_login_on_a_token_with_standard_mechanisms(self, fake_pykcs11, tmp_path):
        from virtual_signer import VirtualSigner
        P = fake_pykcs11
        P.MECHS = {0x1041: P.CKF_SIGN, 0x80420031: P.CKF_SIGN}
        dll = tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll"
        dll.write_bytes(b"x")
        v = VirtualSigner(module_path=str(dll))
        v.login("1234")
        assert v._sign_mechanism == 0x80420031

    def test_pykcs11error_from_login_becomes_runtimeerror(self, fake_pykcs11, tmp_path):
        from pkcs11_signer import PKCS11Signer
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        P.LOGIN_ERROR = P.PyKCS11Error("CKR_PIN_INCORRECT (0x000000A0)")
        dll = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        dll.write_bytes(b"x")
        with pytest.raises(RuntimeError, match="login failed: CKR_PIN_INCORRECT"):
            PKCS11Signer(str(dll)).login("0000")
        assert P.SESSIONS[-1].closed
