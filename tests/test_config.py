"""
sedo_config: config.toml + config_local.toml, profiles, roles, PIN resolution,
and how SEDOClient / the CLI use them. Files are written into tmp_path; the
repository's own config.toml is only touched by test_repo_config_is_valid.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sedo import config as sc
from sedo.client import SEDOClient

ROOT = Path(__file__).resolve().parent.parent


def _write(d: Path, name: str, text: str) -> Path:
    p = d / name
    p.write_text(text, encoding="utf-8")
    return p


BASE = """
[sedo]
url = "https://sedo.example/"
output = "C:/out"

[keys.login]
backend = "opensc"
cert_id = "01"

[keys.sign]
backend = "pkcs11"
cert_id = "02"
slot = 1

[roles]
auth = "login"
sign = "sign"
"""

LOCAL = """
[keys.login]
module = "C:/dll/PKCS11.EKeyAlmaz1C.dll"

[keys.sign]
module = "C:/dll/Av337CryptokiD.dll"
pin_env = "AVTOR_PIN"
"""


# ─── loading and merging ────────────────────────────────────

class TestLoad:
    def test_no_files_is_the_single_key_default(self, tmp_path):
        cfg = sc.load_config(client_dir=tmp_path, env={})
        assert list(cfg.keys) == ["default"]
        assert cfg.roles == {"auth": "default", "sign": "default"}
        assert cfg.keys["default"].backend == "auto"
        assert cfg.sources == []
        assert cfg.sedo_url == "https://sedo.mod.gov.ua" and cfg.output == "./downloads"

    def test_local_merges_per_key_over_base(self, tmp_path):
        _write(tmp_path, "config.toml", BASE)
        _write(tmp_path, "config_local.toml", LOCAL)
        cfg = sc.load_config(client_dir=tmp_path, env={})
        login, sign = cfg.keys["login"], cfg.keys["sign"]
        assert login.backend == "opensc" and login.cert_id == "01"       # from base
        assert login.module == "C:/dll/PKCS11.EKeyAlmaz1C.dll"           # from local
        assert sign.slot == 1 and sign.module == "C:/dll/Av337CryptokiD.dll"
        assert sign.effective_pin_env == "AVTOR_PIN"
        assert login.effective_pin_env == "SEDO_PIN_LOGIN"
        assert cfg.sedo_url == "https://sedo.example"                    # trailing / stripped
        assert [p.name for p in cfg.sources] == ["config.toml", "config_local.toml"]

    def test_roles_and_distinct_profiles(self, tmp_path):
        _write(tmp_path, "config.toml", BASE)
        cfg = sc.load_config(client_dir=tmp_path, env={})
        assert cfg.profile("auth").name == "login" and cfg.profile("sign").name == "sign"
        assert [p.name for p in cfg.distinct_profiles()] == ["login", "sign"]

    def test_one_profile_needs_no_roles(self, tmp_path):
        _write(tmp_path, "config.toml", "[keys.almaz]\nbackend = 'opensc'\n")
        cfg = sc.load_config(client_dir=tmp_path, env={})
        assert cfg.roles == {"auth": "almaz", "sign": "almaz"}
        assert len(cfg.distinct_profiles()) == 1

    def test_one_role_given_the_other_follows(self, tmp_path):
        _write(tmp_path, "config.toml", "[keys.a]\n[keys.b]\n[roles]\nauth = 'b'\n")
        cfg = sc.load_config(client_dir=tmp_path, env={})
        assert cfg.roles == {"auth": "b", "sign": "b"}

    def test_local_single_profile_replaces_the_base_default(self, tmp_path):
        """config.toml ships [keys.default] + roles → default; one real profile
        in config_local.toml must take over without a [roles] table."""
        _write(tmp_path, "config.toml", (ROOT / "config.toml").read_text(encoding="utf-8"))
        _write(tmp_path, "config_local.toml", "[keys.almaz]\nbackend = 'opensc'\n")
        cfg = sc.load_config(client_dir=tmp_path, env={})
        assert cfg.roles == {"auth": "almaz", "sign": "almaz"}
        assert "default" not in cfg.keys

    def test_local_several_profiles_need_roles(self, tmp_path):
        _write(tmp_path, "config.toml", (ROOT / "config.toml").read_text(encoding="utf-8"))
        _write(tmp_path, "config_local.toml", "[keys.a]\n[keys.b]\n")
        with pytest.raises(sc.ConfigError, match=r"several profiles.*add a \[roles\] table"):
            sc.load_config(client_dir=tmp_path, env={})

    def test_local_roles_win_over_base_default(self, tmp_path):
        _write(tmp_path, "config.toml", (ROOT / "config.toml").read_text(encoding="utf-8"))
        _write(tmp_path, "config_local.toml", "[keys.a]\n[keys.b]\n[roles]\nauth = 'a'\nsign = 'b'\n")
        cfg = sc.load_config(client_dir=tmp_path, env={})
        assert cfg.roles == {"auth": "a", "sign": "b"} and "default" not in cfg.keys

    def test_local_overriding_default_itself_keeps_default(self, tmp_path):
        _write(tmp_path, "config.toml", (ROOT / "config.toml").read_text(encoding="utf-8"))
        _write(tmp_path, "config_local.toml", "[keys.default]\nmodule = 'x.dll'\n")
        cfg = sc.load_config(client_dir=tmp_path, env={})
        assert list(cfg.keys) == ["default"] and cfg.keys["default"].module == "x.dll"

    def test_explicit_local_path_replaces_the_default_one(self, tmp_path):
        _write(tmp_path, "config.toml", BASE)
        _write(tmp_path, "config_local.toml", "[keys.login]\nmodule = 'ignored.dll'\n")
        other = _write(tmp_path, "worker7.toml", "[keys.login]\nmodule = 'worker7.dll'\n")
        cfg = sc.load_config(client_dir=tmp_path, local_path=str(other), env={})
        assert cfg.keys["login"].module == "worker7.dll"
        cfg = sc.load_config(client_dir=tmp_path, env={"SEDO_CONFIG": str(other)})
        assert cfg.keys["login"].module == "worker7.dll"

    def test_explicit_local_path_must_exist(self, tmp_path):
        with pytest.raises(sc.ConfigError, match="not found"):
            sc.load_config(client_dir=tmp_path, local_path=str(tmp_path / "nope.toml"), env={})

    def test_sedo_module_env_overrides_the_auth_profile_only(self, tmp_path):
        _write(tmp_path, "config.toml", BASE)
        cfg = sc.load_config(client_dir=tmp_path, env={"SEDO_MODULE": "env.dll"})
        assert cfg.profile("auth").module == "env.dll"
        assert cfg.profile("sign").module is None

    def test_sedo_module_env_reaches_sign_when_it_is_the_same_key(self, tmp_path):
        cfg = sc.load_config(client_dir=tmp_path, env={"SEDO_MODULE": "env.dll"})
        assert cfg.profile("sign").module == "env.dll"


# ─── validation ─────────────────────────────────────────────

class TestValidation:
    @pytest.mark.parametrize("text,match", [
        ("[keys.a]\nbackend = 'pkcs12'\n", "backend"),
        ("[keys.a]\nslot = -1\n", "slot"),
        ("[keys.a]\nslot = true\n", "slot"),
        ("[keys.a]\ncert_id = 'zz'\n", "cert_id"),
        ("[keys.a]\ncert_id = '1'\n", "cert_id"),
        ("[keys.a]\nmechanism = '80420031'\n", "mechanism"),
        ("[keys.a]\ncert_index = -2\n", "cert_index"),
        ("[keys.a]\nmodule = 5\n", "module must be a string"),
        ("[keys.a]\nmodle = 'x'\n", "unknown key.*modle"),
        ("[sedo]\nurll = 'x'\n", "unknown key.*urll"),
        ("[keys.a]\n[keys.b]\n", r"\[roles\] is required"),
        ("[keys.a]\n[roles]\nauth = 'nope'\n", "no such"),
        ("[keys.a]\n[roles]\nverify = 'a'\n", "unknown key.*verify"),
        ("[extra]\nx = 1\n", "unknown key.*extra"),
        ("[keys.a\n", "config.toml"),                       # TOML syntax error names the file
    ])
    def test_rejected(self, tmp_path, text, match):
        _write(tmp_path, "config.toml", text)
        with pytest.raises(sc.ConfigError, match=match):
            sc.load_config(client_dir=tmp_path, env={})

    def test_pin_in_base_file_is_refused(self, tmp_path):
        _write(tmp_path, "config.toml", "[keys.a]\npin = '1234'\n")
        with pytest.raises(sc.ConfigError, match="only accepted in config_local.toml"):
            sc.load_config(client_dir=tmp_path, env={})

    def test_pin_in_local_file_is_accepted_with_a_warning(self, tmp_path, caplog):
        _write(tmp_path, "config_local.toml", "[keys.a]\npin = '1234'\n")
        cfg = sc.load_config(client_dir=tmp_path, env={})
        assert cfg.keys["a"].pin == "1234"
        assert "plain text" in caplog.text

    def test_repo_config_is_valid(self):
        cfg = sc.load_config(client_dir=ROOT, local_path=None, env={})
        # Only the committed base file must count here, whatever a developer
        # keeps in their own config_local.toml.
        assert cfg.keys["default"].backend == "auto"
        assert cfg.roles["auth"] == "default"

    def test_cert_id_is_normalised(self, tmp_path):
        _write(tmp_path, "config.toml", "[keys.a]\ncert_id = '0A'\n")
        assert sc.load_config(client_dir=tmp_path, env={}).keys["a"].cert_id == "0a"


# ─── PIN resolution ─────────────────────────────────────────

class TestPin:
    def _p(self, **kw):
        return sc.KeyProfile(name="sign", **kw)

    def test_argv_wins(self):
        assert sc.resolve_profile_pin(self._p(pin="file"), "argv", env={"SEDO_PIN_SIGN": "e"}) == "argv"

    def test_profile_pin_with_warning(self, caplog):
        assert sc.resolve_profile_pin(self._p(pin="1234"), None, env={}) == "1234"
        assert "config file" in caplog.text

    def test_profile_env_var(self):
        assert sc.resolve_profile_pin(self._p(), None, env={"SEDO_PIN_SIGN": "s", "SEDO_PIN": "g"}) == "s"
        assert sc.resolve_profile_pin(self._p(pin_env="MY"), None, env={"MY": "m", "SEDO_PIN_SIGN": "s"}) == "m"

    def test_generic_sedo_pin_only_when_allowed(self, tmp_path):
        env = {"SEDO_PIN": "login-pin"}
        assert sc.resolve_profile_pin(self._p(), None, allow_generic_env=True, env=env) == "login-pin"
        with patch("getpass.getpass", return_value="typed"):
            assert sc.resolve_profile_pin(self._p(), None, allow_generic_env=False, env=env) == "typed"

    def test_pin_file(self, tmp_path):
        f = tmp_path / "pin"
        f.write_text("  4321\n", encoding="utf-8")
        assert sc.resolve_profile_pin(self._p(pin_file=str(f)), None, env={}) == "4321"

    def test_missing_pin_file_is_a_config_error(self, tmp_path):
        with pytest.raises(sc.ConfigError, match="pin_file"):
            sc.resolve_profile_pin(self._p(pin_file=str(tmp_path / "nope")), None, env={})

    def test_prompt_names_the_profile_and_empty_exits(self):
        with patch("getpass.getpass", return_value="") as gp, pytest.raises(SystemExit) as e:
            sc.resolve_profile_pin(self._p(), None, env={})
        assert e.value.code == 2
        assert "sign" in gp.call_args.args[0]

    def test_default_env_name_is_sanitised(self):
        assert sc.KeyProfile(name="my-key.2").default_pin_env == "SEDO_PIN_MY_KEY_2"

    def test_redacted_hides_the_pin(self):
        cfg = sc.default_config()
        cfg.keys["default"].pin = "1234"
        r = sc.redacted(cfg)
        assert r["keys"]["default"]["pin"] == "***"
        assert r["keys"]["default"]["pin_env"] == "SEDO_PIN_DEFAULT"
        assert "1234" not in json.dumps(r)


# ─── SEDOClient with profiles ───────────────────────────────

class _Signer:
    signature_format = "raw"

    def __init__(self, tag):
        self.tag, self.logins, self.closed = tag, [], False

    def login(self, pin, slot=None):
        self.logins.append((pin, slot))

    def get_certificate(self):
        return b"\x30cert-" + self.tag.encode()

    def sign(self, data):
        return b"sig-" + self.tag.encode()

    def logout(self):
        pass

    def close(self):
        self.closed = True


def _cfg(tmp_path, text=BASE):
    _write(tmp_path, "config.toml", text)
    return sc.load_config(client_dir=tmp_path, env={})


class TestClientProfiles:
    def test_two_profiles_two_signers_with_their_extras(self, tmp_path):
        cfg = _cfg(tmp_path)
        calls = []

        def pick(name, module, key_file=None, **extras):
            calls.append((name, module, key_file, extras))
            return _Signer(name)

        with patch.object(SEDOClient, "_pick_backend", side_effect=pick):
            c = SEDOClient(config=cfg)
        assert calls == [("opensc", None, None, {"cert_id": "01"}),
                         ("pkcs11", None, None, {"cert_id": "02"})]
        assert c.signers["auth"] is not c.signers["sign"]
        assert c.signer is c.signers["auth"]
        c.login("sign", "9999")
        assert c.signers["sign"].logins == [("9999", 1)]          # slot from the profile
        c.login("auth", "1111")
        assert c.signers["auth"].logins == [("1111", None)]
        assert c.sign_document(b"x") == b"sig-pkcs11"
        c.session = MagicMock()
        c.close()
        assert c.signers["auth"].closed and c.signers["sign"].closed

    def test_shared_profile_is_one_signer(self, tmp_path):
        cfg = _cfg(tmp_path, "[keys.k]\nbackend = 'opensc'\n")
        with patch.object(SEDOClient, "_pick_backend", side_effect=lambda *a, **k: _Signer("k")) as pick:
            c = SEDOClient(config=cfg)
        assert pick.call_count == 1
        assert c.signers["auth"] is c.signers["sign"]

    def test_cli_arguments_override_the_auth_profile(self, tmp_path):
        cfg = _cfg(tmp_path)
        calls = []
        with patch.object(SEDOClient, "_pick_backend",
                          side_effect=lambda *a, **k: calls.append((a, k)) or _Signer("x")):
            SEDOClient(config=cfg, backend="virtual", module_path="cli.dll", key_file="k.dat")
        (auth_args, _), (sign_args, _) = calls
        assert auth_args == ("virtual", "cli.dll", "k.dat")
        assert sign_args == ("pkcs11", None, None)

    def test_without_config_everything_is_as_before(self):
        signer = _Signer("legacy")
        with patch.object(SEDOClient, "_pick_backend", return_value=signer) as pick:
            c = SEDOClient(backend="auto")
        pick.assert_called_once_with("auto", None, None)
        assert c.signers == {"auth": signer, "sign": signer} and c.signer is signer

    def test_profile_mechanism_and_cert_index_reach_the_backends(self, tmp_path):
        cfg = _cfg(tmp_path, "[keys.a]\nbackend = 'iit_agent'\ncert_index = 2\n"
                             "[keys.b]\nbackend = 'opensc'\nmechanism = '0x80420032'\n"
                             "[roles]\nauth = 'a'\nsign = 'b'\n")
        calls = []
        with patch.object(SEDOClient, "_pick_backend",
                          side_effect=lambda *a, **k: calls.append(k) or _Signer("x")):
            SEDOClient(config=cfg)
        assert calls == [{"cert_index": 2}, {"mechanism": "0x80420032"}]


class TestBackendExtras:
    def test_opensc_profile_mechanism_skips_discovery(self, tmp_path):
        tool = tmp_path / "pkcs11-tool"
        tool.write_bytes(b"x")
        dll = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        dll.write_bytes(b"x")
        with patch("sedo.opensc_signer.OpenSCSigner._find_tool", return_value=str(tool)), \
             patch("sedo.opensc_signer.subprocess.run") as run:
            with patch.object(SEDOClient, "_discover_opensc_mechanism") as disc:
                c = SEDOClient.__new__(SEDOClient)
                c.sedo_url = "x"
                s = c._pick_backend("opensc", str(dll), None, cert_id="07", mechanism="0x80420032")
        disc.assert_not_called()
        run.assert_not_called()
        assert s._mechanism == "0x80420032" and s._cert_id == "07"

    def test_pkcs11_profile_cert_id_and_mechanism(self, fake_pykcs11, tmp_path):
        from sedo.pkcs11_signer import PKCS11Signer
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN, 0x80420032: P.CKF_SIGN}
        k1, k2, c1, c2 = object(), object(), object(), object()
        P.PRIVATE_KEYS, P.CERTS = [k1, k2], [c1, c2]
        P.OBJ_ATTRS = {k1: {P.CKA_ID: b"\x01"}, c1: {P.CKA_ID: b"\x01", P.CKA_VALUE: b"one"},
                       k2: {P.CKA_ID: b"\x02"}, c2: {P.CKA_ID: b"\x02", P.CKA_VALUE: b"two"}}
        dll = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        dll.write_bytes(b"x")
        s = PKCS11Signer(str(dll), cert_id="02", mechanism=0x80420032)
        s.login("1234")
        assert s.get_certificate() == b"two"
        s.sign(b"d")
        assert P.SIGN_CALLS[-1] == (k2, 0x80420032)

    def test_pkcs11_missing_cert_id_is_an_error_not_a_fallback(self, fake_pykcs11, tmp_path):
        from sedo.pkcs11_signer import PKCS11Signer
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        dll = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
        dll.write_bytes(b"x")
        with pytest.raises(RuntimeError, match="No private key with CKA_ID 09"):
            PKCS11Signer(str(dll), cert_id="09").login("1234")
        assert P.SESSIONS[-1].closed

    def test_iit_adapter_cert_index(self):
        from sedo.client import IITAgentAdapter
        client = MagicMock()
        client.enum_key_media_devices.return_value = [{"devIndex": 0}]
        client.enum_own_certificates.return_value = [{}, {}]
        client.get_own_certificate.return_value = {"data": "3082"}
        IITAgentAdapter(client, cert_index=1).login("1")
        client.get_own_certificate.assert_called_once_with(1)
        with pytest.raises(RuntimeError, match="out of range"):
            IITAgentAdapter(client, cert_index=5).login("1")


# ─── CLI ────────────────────────────────────────────────────

class TestCLI:
    def _run(self, tmp_path, monkeypatch, argv, cfg_text=None, env=None):
        from sedo.client import main
        monkeypatch.chdir(tmp_path)
        for var in ("SEDO_PIN", "SEDO_MODULE", "SEDO_CONFIG"):
            monkeypatch.delenv(var, raising=False)
        for k, v in (env or {}).items():
            monkeypatch.setenv(k, v)
        if cfg_text is not None:
            local = _write(tmp_path, "local.toml", cfg_text)
            argv = argv + ["--config", str(local)]
        monkeypatch.setattr(sys, "argv", ["sedo-client"] + argv)
        return main

    def test_show_config_prints_redacted_json(self, tmp_path, monkeypatch, capsys):
        main = self._run(tmp_path, monkeypatch, ["--show-config"],
                         "[keys.k]\nbackend='opensc'\npin='1234'\n")
        main()
        out = json.loads(capsys.readouterr().out)
        assert out["keys"]["k"]["pin"] == "***" and out["roles"]["auth"] == "k"
        assert "1234" not in json.dumps(out)

    def test_config_error_exits_2(self, tmp_path, monkeypatch, capsys):
        main = self._run(tmp_path, monkeypatch, [], "[keys.k]\nbackend='nope'\n")
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 2

    def test_sign_file_uses_the_sign_profile_and_its_pin(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "doc.bin").write_bytes(b"payload")
        main = self._run(tmp_path, monkeypatch, ["--sign-file", "doc.bin"],
                         "[keys.login]\nbackend='opensc'\n[keys.doc]\nbackend='pkcs11'\n"
                         "[roles]\nauth='login'\nsign='doc'\n",
                         env={"SEDO_PIN": "login-pin", "SEDO_PIN_DOC": "doc-pin"})
        fake_ctx = MagicMock()
        sedo = fake_ctx.__enter__.return_value
        sedo.sign_document.return_value = b"\x01\x02"
        sedo.signers = {"sign": MagicMock(signature_format="raw")}
        with patch("sedo.client.SEDOClient", return_value=fake_ctx) as cls:
            main()
        sedo.login.assert_called_once_with("sign", "doc-pin")        # not the login key's PIN
        sedo.sign_document.assert_called_once_with(b"payload")
        sedo.authorize.assert_not_called()
        assert (tmp_path / "doc.bin.sig").read_bytes() == b"\x01\x02"
        assert cls.call_args.kwargs["config"].roles["sign"] == "doc"
        assert "profile doc" in capsys.readouterr().out

    def test_sign_file_separate_key_does_not_take_sedo_pin(self, tmp_path, monkeypatch):
        (tmp_path / "doc.bin").write_bytes(b"p")
        main = self._run(tmp_path, monkeypatch, ["--sign-file", "doc.bin"],
                         "[keys.login]\n[keys.doc]\n[roles]\nauth='login'\nsign='doc'\n",
                         env={"SEDO_PIN": "login-pin"})
        with patch("sedo.client.SEDOClient"), patch("getpass.getpass", return_value="") as gp, \
             pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 2 and gp.called            # asked, not reused

    def test_output_and_since_default_from_config(self, tmp_path, monkeypatch):
        main = self._run(tmp_path, monkeypatch, ["--fetch", "--pin", "1"],
                         "[sedo]\noutput='from-config'\nsince='2026-01-02'\n[keys.k]\n")
        fake_ctx = MagicMock()
        fake_ctx.__enter__.return_value.fetch_inbox.return_value = []
        with patch("sedo.client.SEDOClient", return_value=fake_ctx):
            main()
        fake_ctx.__enter__.return_value.fetch_inbox.assert_called_once_with(since="2026-01-02")
        assert (tmp_path / "from-config").is_dir()

    def test_auth_pin_comes_from_the_profile_env(self, tmp_path, monkeypatch):
        main = self._run(tmp_path, monkeypatch, [], "[keys.almaz]\n",
                         env={"SEDO_PIN_ALMAZ": "profile-pin"})
        fake_ctx = MagicMock()
        with patch("sedo.client.SEDOClient", return_value=fake_ctx), patch("getpass.getpass") as gp:
            main()
        gp.assert_not_called()
        fake_ctx.__enter__.return_value.authorize.assert_called_once_with("profile-pin")
