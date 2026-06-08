"""
Unit tests for Avest CC-337 / SecureToken-338 support and
multi-vendor DSTU 4145 mechanism selection.

Pure-Python logic — no PyKCS11 or hardware needed.
"""

import pytest


class TestDetectTokenVendor:
    def test_iit_almaz_hw(self):
        from mechanism_ids import detect_token_vendor
        assert detect_token_vendor("PKCS11.EKeyAlmaz1C.dll") == "iit"

    def test_iit_almaz_virtual(self):
        from mechanism_ids import detect_token_vendor
        assert detect_token_vendor("PKCS11.Virtual.EKeyAlmaz1C.dll") == "iit_virtual"

    def test_iit_crystal(self):
        from mechanism_ids import detect_token_vendor
        assert detect_token_vendor("PKCS11.EKeyCrystal1.dll") == "iit"

    def test_avest_av337(self):
        from mechanism_ids import detect_token_vendor
        assert detect_token_vendor(r"C:\Avest\Av337CryptokiD.dll") == "avest"

    def test_avest_nxt(self):
        from mechanism_ids import detect_token_vendor
        assert detect_token_vendor("avcryptokinxt.dll") == "avest"

    def test_avest_efitkey(self):
        from mechanism_ids import detect_token_vendor
        assert detect_token_vendor("efitkeynxt.dll") == "avest"

    def test_unknown(self):
        from mechanism_ids import detect_token_vendor
        assert detect_token_vendor("some_random.dll") == "unknown"


class TestDetectMechanismAvest:
    def test_av337_is_standard_dstu(self):
        """ST-338 (Av337CryptokiD.dll) uses standard 0x00000352."""
        from mechanism_ids import detect_dstu4145_mechanism, CKM_DSTU4145
        assert detect_dstu4145_mechanism("Av337CryptokiD.dll") == CKM_DSTU4145

    def test_almaz_is_vendor_dstu(self):
        from mechanism_ids import detect_dstu4145_mechanism, CKM_IIT_DSTU4145
        assert detect_dstu4145_mechanism("PKCS11.EKeyAlmaz1C.dll") == CKM_IIT_DSTU4145


class TestPickSignMechanism:
    def test_picks_iit_vendor_first(self):
        """When both IIT and standard DSTU present, IIT vendor wins."""
        from mechanism_ids import pick_sign_mechanism, CKM_IIT_DSTU4145
        available = [0x00000352, 0x80420031, 0x00000001]
        assert pick_sign_mechanism(available) == CKM_IIT_DSTU4145

    def test_picks_standard_dstu_for_avest(self):
        """Avest ST-338 exposes only standard 0x00000352 (no vendor ID)."""
        from mechanism_ids import pick_sign_mechanism, CKM_DSTU4145
        # RSA + ECDSA + standard DSTU — must skip RSA/ECDSA, pick DSTU
        available = [0x00000001, 0x00001042, 0x00000352]
        assert pick_sign_mechanism(available) == CKM_DSTU4145

    def test_returns_none_when_no_known_dstu(self):
        """No known DSTU mechanism → None (caller decides fallback)."""
        from mechanism_ids import pick_sign_mechanism
        available = [0x00000001, 0x00001042]  # RSA, ECDSA only
        assert pick_sign_mechanism(available) is None

    def test_accepts_pykcs11_ckmechanism_objects(self):
        """Works with objects that int() to a mechanism ID (PyKCS11 returns these)."""
        from mechanism_ids import pick_sign_mechanism, CKM_DSTU4145

        class FakeMech:
            def __init__(self, v):
                self._v = v
            def __int__(self):
                return self._v

        available = [FakeMech(0x00000001), FakeMech(0x00000352)]
        assert pick_sign_mechanism(available) == CKM_DSTU4145


class TestModuleSearchPaths:
    def test_avest_paths_in_defaults(self):
        """PKCS11Signer search list includes Avest modules."""
        from pkcs11_signer import PKCS11Signer
        joined = " ".join(PKCS11Signer.DEFAULT_MODULE_PATHS)
        assert "Av337CryptokiD.dll" in joined
        assert "avcryptokinxt.dll" in joined

    def test_iit_paths_still_present(self):
        from pkcs11_signer import PKCS11Signer
        joined = " ".join(PKCS11Signer.DEFAULT_MODULE_PATHS)
        assert "PKCS11.EKeyAlmaz1C.dll" in joined
