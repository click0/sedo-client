"""
sedo_check (`--check`): the PIN-less setup check. Unit tests on fakes here;
the real-stack run is in test_integration_softhsm.py::TestCheck.
"""

import struct
import subprocess
from unittest.mock import patch

import pytest

import sedo_check as chk
from sedo_config import KeyProfile, default_config


def _pe(machine: int) -> bytes:
    head = bytearray(b"MZ" + b"\0" * 0x3E)
    struct.pack_into("<I", head, 0x3C, 0x40)
    return bytes(head) + b"PE\0\0" + struct.pack("<H", machine) + b"\0" * 20


class TestBitness:
    @pytest.mark.parametrize("machine,bits", [(0x014C, 32), (0x8664, 64), (0xAA64, 64)])
    def test_pe(self, tmp_path, machine, bits):
        f = tmp_path / "x.dll"
        f.write_bytes(_pe(machine))
        assert chk.pe_bitness(f) == bits

    def test_non_pe_and_missing(self, tmp_path):
        f = tmp_path / "x.so"
        f.write_bytes(b"\x7fELF" + b"\0" * 100)
        assert chk.pe_bitness(f) is None
        assert chk.pe_bitness(tmp_path / "nope") is None

    def test_python_bitness(self):
        assert chk.python_bitness() in (32, 64)


class TestReport:
    def test_ok_and_problems(self):
        r = chk.Report()
        r.add("", "head")
        r.add(chk.OK, "fine")
        assert r.ok and r.problems == 0
        r.add(chk.WARN, "hm")
        assert r.ok and r.problems == 1
        r.add(chk.FAIL, "bad")
        assert not r.ok and r.problems == 2
        assert r.render().splitlines() == ["head", "  ✓ fine", "  ! hm", "  ✗ bad"]


class TestPinSource:
    def test_profile_env_set(self, monkeypatch):
        monkeypatch.setenv("SEDO_PIN_DOC", "x")
        assert chk._pin_source(KeyProfile("doc"), False)[0] == chk.OK

    def test_generic_only_for_auth_key(self, monkeypatch):
        monkeypatch.delenv("SEDO_PIN_DOC", raising=False)
        monkeypatch.setenv("SEDO_PIN", "x")
        assert chk._pin_source(KeyProfile("doc"), True)[0] == chk.OK
        level, text = chk._pin_source(KeyProfile("doc"), False)
        assert level == chk.WARN and "SEDO_PIN_DOC" in text and "інтерактивний" in text

    def test_pin_file(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SEDO_PIN_DOC", raising=False)
        monkeypatch.delenv("SEDO_PIN", raising=False)
        f = tmp_path / "pin"
        assert chk._pin_source(KeyProfile("doc", pin_file=str(f)), False)[0] == chk.FAIL
        f.write_text("1", encoding="utf-8")
        assert chk._pin_source(KeyProfile("doc", pin_file=str(f)), False)[0] == chk.OK

    def test_pin_in_config_is_a_warning(self):
        assert chk._pin_source(KeyProfile("doc", pin="1"), False)[0] == chk.WARN


LIST_SLOTS = b"Available slots:\nSlot 0 (0x0): Avtor SecureToken 0\n  token label        : CC337 Signature Device\n"
LIST_MECHS = b"Supported mechanisms:\n  mechtype-0x80420014, keySize={32,32}, sign, verify\n  mechtype-0x80420031, keySize={163,509}, hw, sign, verify, EC F_2M\n"
LIST_CERTS = b"Certificate Object; type = X.509 cert\n  label:      a\n  ID:         01\nCertificate Object; type = X.509 cert\n  ID:         02\n"


def _fake_run(cmd, **kw):
    args = list(cmd)
    assert "--login" not in args and "--pin" not in args, "the check must never use a PIN"
    out = LIST_SLOTS if "--list-slots" in args else LIST_MECHS if "--list-mechanisms" in args \
        else LIST_CERTS if "--list-objects" in args else b""
    return subprocess.CompletedProcess(args, 0, stdout=out, stderr=b"")


class TestOpenSCCheck:
    def _module(self, tmp_path, machine=0x014C):
        m = tmp_path / "Av337CryptokiD.dll"
        m.write_bytes(_pe(machine))
        tool = tmp_path / "pkcs11-tool.exe"
        tool.write_bytes(_pe(0x014C))
        return str(m), str(tool)

    def test_happy_path(self, tmp_path, monkeypatch):
        module, tool = self._module(tmp_path)
        monkeypatch.setenv("SEDO_PIN_LOGIN", "x")
        rep = chk.Report()
        with patch("opensc_signer.OpenSCSigner._find_tool", return_value=tool), \
             patch("opensc_signer.subprocess.run", side_effect=_fake_run):
            chk.check_profile(KeyProfile("login", backend="opensc", module=module, cert_id="01"),
                              "https://sedo", True, rep)
        text = rep.render()
        assert rep.ok, text
        assert "32-bit" in text and "CC337" in text
        assert "0x80420031 (зі списку токена)" in text     # the MAC 0x80420014 was not chosen
        assert "cert_id 01 присутній" in text and "SEDO_PIN_LOGIN задано" in text

    def test_missing_cert_id_fails(self, tmp_path, monkeypatch):
        module, tool = self._module(tmp_path)
        rep = chk.Report()
        with patch("opensc_signer.OpenSCSigner._find_tool", return_value=tool), \
             patch("opensc_signer.subprocess.run", side_effect=_fake_run):
            chk.check_profile(KeyProfile("login", backend="opensc", module=module, cert_id="07"),
                              "https://sedo", True, rep)
        assert not rep.ok and "cert_id 07 НЕМАЄ" in rep.render()

    def test_bitness_mismatch_fails(self, tmp_path):
        module, _ = self._module(tmp_path, machine=0x014C)
        tool64 = tmp_path / "tool64.exe"
        tool64.write_bytes(_pe(0x8664))
        rep = chk.Report()
        with patch("opensc_signer.OpenSCSigner._find_tool", return_value=str(tool64)), \
             patch("opensc_signer.subprocess.run", side_effect=_fake_run):
            chk.check_profile(KeyProfile("login", backend="opensc", module=module), "u", True, rep)
        assert not rep.ok and "sc_dlopen failed" in rep.render()

    def test_missing_module_fails_without_running_anything(self, tmp_path):
        rep = chk.Report()
        with patch("opensc_signer.subprocess.run") as run:
            chk.check_profile(KeyProfile("login", backend="opensc", module=str(tmp_path / "no.dll")),
                              "u", True, rep)
        run.assert_not_called()
        assert not rep.ok and "не існує" in rep.render()

    def test_no_token_fails(self, tmp_path):
        module, tool = self._module(tmp_path)

        def no_token(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=b"Available slots:\nNo slots.\n", stderr=b"")
        rep = chk.Report()
        with patch("opensc_signer.OpenSCSigner._find_tool", return_value=tool), \
             patch("opensc_signer.subprocess.run", side_effect=no_token):
            chk.check_profile(KeyProfile("login", backend="opensc", module=module), "u", True, rep)
        assert not rep.ok and "токен не видно" in rep.render()


class TestPyKCS11Check:
    def test_happy_path_on_the_fake(self, fake_pykcs11, tmp_path, monkeypatch):
        P = fake_pykcs11
        P.MECHS = {0x80420014: P.CKF_SIGN, 0x80420031: P.CKF_SIGN}
        c1, c2 = object(), object()
        P.CERTS = [c1, c2]
        P.OBJ_ATTRS = {c1: {P.CKA_ID: b"\x01"}, c2: {P.CKA_ID: b"\x02"}}
        monkeypatch.setenv("SEDO_PIN_DOC", "x")
        module = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        module.write_bytes(b"not a PE")                    # bitness unknown → no mismatch check
        rep = chk.Report()
        chk.check_profile(KeyProfile("doc", backend="pkcs11", module=str(module), cert_id="02"),
                          "u", False, rep)
        text = rep.render()
        assert rep.ok, text
        assert "FakeToken" in text and "0x80420031" in text and "cert_id 02 присутній" in text
        assert not any(s.logged_in for s in P.SESSIONS)     # public session only
        assert P.UNLOADS == [str(module)]

    def test_pinned_unsupported_mechanism_fails(self, fake_pykcs11, tmp_path):
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        module = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        module.write_bytes(b"x")
        rep = chk.Report()
        chk.check_profile(KeyProfile("doc", backend="pkcs11", module=str(module), mechanism="0x80420099"),
                          "u", False, rep)
        assert not rep.ok and "не підтримує" in rep.render()


class TestRunChecks:
    def test_report_shape_and_never_aborts(self, tmp_path):
        cfg = default_config()
        cfg.keys["default"].backend = "opensc"
        cfg.keys["default"].module = str(tmp_path / "missing.dll")
        with patch("sedo_check.check_profile", side_effect=RuntimeError("boom")):
            rep = chk.run_checks(cfg)
        text = rep.render()
        assert "Ролі: auth → default, sign → default" in text
        assert "перевірка профілю впала: RuntimeError: boom" in text
        assert text.endswith("1 проблем(и), див. ✗ / ! вище")
        assert not rep.ok

    def test_cli_exit_codes(self, tmp_path, monkeypatch, capsys):
        import sys
        from sedo_client import main
        monkeypatch.chdir(tmp_path)
        (tmp_path / "l.toml").write_text("[keys.k]\nbackend='opensc'\nmodule='nope.dll'\n", encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["sedo-client", "--config", "l.toml", "--check"])
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 1
        assert "модуль не існує" in capsys.readouterr().out
