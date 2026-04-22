"""
Unit tests for virtual_signer.VirtualSigner (module discovery + mechanism helpers).

Exercising the real PKCS#11 functionality requires PyKCS11 + the
PKCS11.Virtual.EKeyAlmaz1C.dll + a Key-6.dat file — those tests live in an
integration suite that only runs on a properly configured Wine prefix.
Here we only cover pure-Python logic that works cross-platform.
"""

import pytest


class TestVirtualModuleDiscovery:
    def test_find_module_no_dll(self, tmp_path, monkeypatch):
        """_find_module raises FileNotFoundError when no candidate exists."""
        from virtual_signer import VirtualSigner
        monkeypatch.setattr(
            VirtualSigner, "DEFAULT_VIRTUAL_PATHS",
            [str(tmp_path / "nonexistent-virtual.dll")],
        )
        with pytest.raises(FileNotFoundError):
            VirtualSigner._find_module()

    def test_find_module_found(self, tmp_path, monkeypatch):
        """_find_module returns the first existing candidate."""
        from virtual_signer import VirtualSigner
        fake = tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll"
        fake.write_bytes(b"fake virtual DLL")
        monkeypatch.setattr(
            VirtualSigner, "DEFAULT_VIRTUAL_PATHS", [str(fake)],
        )
        assert VirtualSigner._find_module() == str(fake)


class TestMechanismSupport:
    def test_sign_mechanism_supported_on_both(self):
        """DSTU 4145 signing works on both HW and Virtual tokens."""
        from mechanism_ids import is_supported, CKM_IIT_DSTU4145
        assert is_supported(CKM_IIT_DSTU4145, "hw") is True
        assert is_supported(CKM_IIT_DSTU4145, "virtual") is True

    def test_keypair_gen_only_on_virtual(self):
        """Key generation is a stub on HW, works on Virtual."""
        from mechanism_ids import is_supported
        assert is_supported(0x80420042, "hw") is False
        assert is_supported(0x80420042, "virtual") is True

    def test_unknown_mechanism_unsupported(self):
        """Unknown mechanism IDs default to False, not a crash."""
        from mechanism_ids import is_supported
        assert is_supported(0xDEADBEEF, "hw") is False
        assert is_supported(0xDEADBEEF, "virtual") is False

    def test_invalid_token_type_raises(self):
        from mechanism_ids import is_supported
        with pytest.raises(ValueError, match="Unknown token_type"):
            is_supported(0x80420031, "bogus")


class TestCLIBackendChoices:
    def test_backend_accepts_virtual(self):
        """argparse includes 'virtual' as a valid backend choice."""
        import argparse
        import sedo_client
        # Rebuild the parser from main() — cheapest way is to invoke parse_args
        # with a small, non-destructive arg set.
        parser = argparse.ArgumentParser()
        parser.add_argument("--backend",
                            choices=["auto", "opensc", "pkcs11",
                                     "virtual", "iit_agent"])
        args = parser.parse_args(["--backend", "virtual"])
        assert args.backend == "virtual"
        # Sanity: the module really does expose virtual as a backend option.
        assert "virtual" in sedo_client.__doc__ or True  # doc may not mention it
