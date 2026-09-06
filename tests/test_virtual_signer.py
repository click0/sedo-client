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


class TestDetectDSTU4145:
    def test_almaz_hw_module(self):
        from mechanism_ids import detect_dstu4145_mechanism, CKM_IIT_DSTU4145
        assert detect_dstu4145_mechanism(r"C:\libs\PKCS11.EKeyAlmaz1C.dll") == CKM_IIT_DSTU4145

    def test_almaz_virtual_module(self):
        """Virtual module name still contains 'ekeyalmaz1c' — same mechanism."""
        from mechanism_ids import detect_dstu4145_mechanism, CKM_IIT_DSTU4145
        assert detect_dstu4145_mechanism("PKCS11.Virtual.EKeyAlmaz1C.dll") == CKM_IIT_DSTU4145

    def test_avest_module(self):
        from mechanism_ids import detect_dstu4145_mechanism, CKM_DSTU4145
        assert detect_dstu4145_mechanism("avcryptokinxt.dll") == CKM_DSTU4145

    def test_efitkey_module(self):
        from mechanism_ids import detect_dstu4145_mechanism, CKM_DSTU4145
        assert detect_dstu4145_mechanism("efitkeynxt.dll") == CKM_DSTU4145

    def test_unknown_module_defaults_to_iit(self):
        from mechanism_ids import detect_dstu4145_mechanism, CKM_IIT_DSTU4145
        assert detect_dstu4145_mechanism("random_pkcs11.dll") == CKM_IIT_DSTU4145


class TestCLIBackendChoices:
    """Check the REAL parser (sedo_client._build_parser), not a local copy."""

    @pytest.mark.parametrize("backend",
                             ["auto", "opensc", "pkcs11", "virtual", "iit_agent"])
    def test_real_parser_accepts_backend(self, backend):
        from sedo_client import _build_parser
        assert _build_parser().parse_args(["--backend", backend]).backend == backend

    def test_real_parser_rejects_unknown_backend(self):
        from sedo_client import _build_parser
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["--backend", "bogus"])

    def test_key_file_help_is_honest(self):
        """--key-file only validates; help must not promise the DLL loads it."""
        from sedo_client import _build_parser
        help_text = _build_parser().format_help()
        assert "--key-file" in help_text
        assert "valid" in help_text.lower()
