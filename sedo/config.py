"""
Конфігурація sedo-client: config.toml + config_local.toml, профілі ключів, ролі.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.37
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026

Два файли поруч із клієнтом, як у Django/Flask:

- ``config.toml`` — базовий, у репозиторії: URL, каталог завантажень, ролі,
  типові значення профілів. Без секретів і без машинних шляхів.
- ``config_local.toml`` — у .gitignore, свій на кожну машину: шляхи до DLL,
  який токен за яку роль, звідки брати PIN. Ansible генерує його з Vault.

Порядок перекриття: config.toml → config_local.toml → змінні SEDO_* → CLI.
Злиття по ключах: локальний файл може задати лише ``module`` профілю, решта
полів береться з базового.

Профіль ключа (``[keys.<name>]``) описує один ключ: backend, модуль, слот,
CKA_ID, джерело PIN. Ролі (``[roles]``) кажуть, який профіль логіниться в
СЕДО (``auth``) і який підписує документи (``sign``). Обидві ролі на один
профіль — це сьогоднішня поведінка з одним ключем.

PIN у файлах не зберігається: профіль лише каже, звідки його взяти
(``pin_env``, типово ``SEDO_PIN_<NAME>``; ``pin_file``; інакше запит).
``pin`` у файлі приймається лише з config_local.toml і з попередженням.
"""

import codecs
import copy
import dataclasses
import logging
import os
import re
import stat
import sys
import tomllib
import unicodedata
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

__all__ = [
    "Config", "KeyProfile", "ConfigError", "load_config", "default_config",
    "default_config_dir", "user_config_dir", "resolve_profile_pin", "redacted",
    "CONFIG_BASE", "CONFIG_LOCAL", "CONFIG_ENV", "ROLES", "BACKENDS",
]

CONFIG_BASE = "config.toml"
CONFIG_LOCAL = "config_local.toml"
# Explicit path of the local file (replaces config_local.toml next to the client).
CONFIG_ENV = "SEDO_CONFIG"
# Directory name under %APPDATA% / $XDG_CONFIG_HOME for an installed package.
APP_DIR = "sedo-client"

# One level above this package: the repository root in a checkout (or an
# editable install), but site-packages once the wheel is installed.
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
# Files that exist in a source tree and are never shipped in the wheel.
_CHECKOUT_MARKERS = ("pyproject.toml", CONFIG_BASE)

ROLES = ("auth", "sign")
BACKENDS = ("auto", "opensc", "pkcs11", "virtual", "iit_agent")

_SEDO_KEYS = {"url", "output", "since"}
_PROFILE_KEYS = {"backend", "module", "slot", "cert_id", "cert_index", "key_file",
                 "mechanism", "pin_env", "pin_file", "pin"}
_TOP_KEYS = {"sedo", "keys", "roles"}
# Both used with fullmatch: "$" also matches before a trailing newline, so
# cert_id = "01\n" passed and went to pkcs11-tool as --id.
_HEX_ID_RE = re.compile(r"(?:[0-9A-Fa-f]{2})+")
_MECH_RE = re.compile(r"0x[0-9A-Fa-f]{1,8}")


class ConfigError(ValueError):
    """Invalid or unreadable configuration (file and key named in the message)."""


@dataclasses.dataclass
class KeyProfile:
    """One key: where it lives and how to reach it. ``pin`` is never stored by us."""
    name: str
    backend: str = "auto"
    module: Optional[str] = None
    slot: Optional[int] = None
    cert_id: Optional[str] = None        # CKA_ID hex, PKCS#11 backends
    cert_index: Optional[int] = None     # iit_agent: index in EnumOwnCertificates
    key_file: Optional[str] = None       # virtual: Key-6.dat
    mechanism: Optional[str] = None      # "0x80420031"; default: ask the token
    pin_env: Optional[str] = None        # default SEDO_PIN_<NAME>
    pin_file: Optional[str] = None
    pin: Optional[str] = None            # config_local.toml only, discouraged

    @property
    def default_pin_env(self) -> str:
        return "SEDO_PIN_" + re.sub(r"[^A-Za-z0-9]+", "_", self.name).upper()

    @property
    def effective_pin_env(self) -> str:
        return self.pin_env or self.default_pin_env


@dataclasses.dataclass
class Config:
    sedo_url: str = "https://sedo.mod.gov.ua"
    output: str = "./downloads"
    since: Optional[str] = None
    keys: dict = dataclasses.field(default_factory=dict)      # name → KeyProfile
    roles: dict = dataclasses.field(default_factory=dict)     # role → profile name
    sources: list = dataclasses.field(default_factory=list)   # files actually read
    config_dir: Optional[Path] = None                         # where both files were looked for

    def profile(self, role: str) -> KeyProfile:
        if role not in self.roles:
            raise ConfigError(f"no profile assigned to role {role!r}")
        return self.keys[self.roles[role]]

    def distinct_profiles(self) -> list:
        """Profiles in role order, each once — two roles on one key share a session."""
        seen, out = set(), []
        for role in ROLES:
            name = self.roles.get(role)
            if name and name not in seen:
                seen.add(name)
                out.append(self.keys[name])
        return out


def default_config() -> Config:
    """No files at all: one profile "default" for both roles — the pre-config behaviour."""
    return Config(keys={"default": KeyProfile("default")},
                  roles={"auth": "default", "sign": "default"})


def user_config_dir(env: Optional[dict] = None) -> Path:
    """
    The per-user config directory of an installed package:
    %APPDATA%\\sedo-client on Windows, $XDG_CONFIG_HOME/sedo-client (default
    ~/.config/sedo-client) elsewhere.
    """
    env = os.environ if env is None else env
    if sys.platform == "win32":
        base = env.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = env.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_DIR


def default_config_dir(env: Optional[dict] = None) -> Path:
    """Where config.toml / config_local.toml live.

    - A PyInstaller binary: next to the .exe.
    - A source tree (the documented deployment: git clone → C:\\sedo-client,
      `python sedo_client.py`; also `pip install -e .`): the repository root,
      one level above this package.
    - An installed wheel (`pip install .` → `sedo-client`): the per-user
      directory from user_config_dir(). One level above the package is
      site-packages there, and that is where 0.33 looked — so a pip-installed
      client never found config_local.toml without --config / SEDO_CONFIG.

    A source tree is told apart by files the wheel never ships.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    if any((_PACKAGE_ROOT / name).is_file() for name in _CHECKOUT_MARKERS):
        return _PACKAGE_ROOT
    return user_config_dir(env)


def _read_toml(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise ConfigError(f"{path}: {e}") from e
    try:
        # utf-8-sig: Notepad and PowerShell 5 (-Encoding UTF8) put a BOM first,
        # and tomllib answered "Invalid statement (at line 1, column 1)" for a
        # file that looks perfectly fine in the editor.
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        # UTF-16 (PowerShell 5 ">" / Out-File) or an ANSI code page with a
        # Cyrillic path in it. tomllib.load raised UnicodeDecodeError, which is
        # neither TOMLDecodeError nor OSError: main() showed a traceback.
        kind = "UTF-16" if raw[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE) else "not UTF-8"
        raise ConfigError(f"{path}: the file is {kind} (byte {e.start}); "
                          "save it as UTF-8") from e
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from e


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _check_keys(section: str, data: dict, allowed: set, source: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"{source}: unknown key(s) in [{section}]: {', '.join(unknown)}; "
                          f"allowed: {', '.join(sorted(allowed))}")


def _validate_raw(data: dict, source: str, is_local: bool) -> None:
    """Shape checks on one file, before merging (so the message names the file)."""
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: top level must be a table")
    _check_keys("", data, _TOP_KEYS, source)
    sedo = data.get("sedo", {})
    if not isinstance(sedo, dict):
        raise ConfigError(f"{source}: [sedo] must be a table")
    _check_keys("sedo", sedo, _SEDO_KEYS, source)
    keys = data.get("keys", {})
    if not isinstance(keys, dict):
        raise ConfigError(f"{source}: [keys] must hold [keys.<name>] tables")
    for name, prof in keys.items():
        if not isinstance(prof, dict):
            raise ConfigError(f"{source}: [keys.{name}] must be a table")
        _check_keys(f"keys.{name}", prof, _PROFILE_KEYS, source)
        if "pin" in prof and not is_local:
            raise ConfigError(f"{source}: [keys.{name}].pin — a PIN is only accepted in "
                              f"{CONFIG_LOCAL} (and even there prefer pin_env / pin_file)")
    roles = data.get("roles", {})
    if not isinstance(roles, dict):
        raise ConfigError(f"{source}: [roles] must be a table")
    _check_keys("roles", roles, set(ROLES), source)
    for role, target in roles.items():
        # auth = ["login"] or auth = {…}: unhashable, and _build() looked it
        # up in a dict — TypeError, a traceback instead of this message.
        if not isinstance(target, str):
            raise ConfigError(f"{source}: [roles].{role} must be the name of a "
                              f"[keys.<name>] profile, in quotes")


def _build(merged: dict, sources: list, roles_from_local: bool = False) -> Config:
    cfg = default_config()
    cfg.sources = sources
    sedo = merged.get("sedo", {})
    cfg.sedo_url = str(sedo.get("url", cfg.sedo_url)).rstrip("/")
    cfg.output = str(sedo.get("output", cfg.output))
    cfg.since = sedo.get("since")
    if cfg.since is not None:
        cfg.since = str(cfg.since)

    keys = merged.get("keys", {})
    if keys:
        cfg.keys = {}
    for name, prof in keys.items():
        p = KeyProfile(name=str(name))
        for field, value in prof.items():
            setattr(p, field, value)
        where = f"[keys.{name}]"
        if p.backend not in BACKENDS:
            raise ConfigError(f"{where}.backend = {p.backend!r}; expected one of {', '.join(BACKENDS)}")
        if p.slot is not None and (isinstance(p.slot, bool) or not isinstance(p.slot, int) or p.slot < 0):
            raise ConfigError(f"{where}.slot must be a non-negative integer")
        if p.cert_index is not None and (isinstance(p.cert_index, bool)
                                         or not isinstance(p.cert_index, int) or p.cert_index < 0):
            raise ConfigError(f"{where}.cert_index must be a non-negative integer")
        if p.cert_id is not None:
            p.cert_id = str(p.cert_id).lower()
            if not _HEX_ID_RE.fullmatch(p.cert_id):
                raise ConfigError(f"{where}.cert_id must be hex bytes like \"01\" or \"0a2b\"")
        if p.mechanism is not None:
            p.mechanism = str(p.mechanism)
            if not _MECH_RE.fullmatch(p.mechanism):
                raise ConfigError(f"{where}.mechanism must look like \"0x80420031\"")
            # A pinned mechanism skips discovery, and with it the guard that
            # keeps choose_sign_mechanism off the MACs: "0x80420014" (the id
            # OPENSC-QUICKSTART gave before 0.29) went to C_Sign as it was.
            from .mechanism_ids import NON_SIGNATURE_MECHANISMS
            if int(p.mechanism, 16) in NON_SIGNATURE_MECHANISMS:
                raise ConfigError(f"{where}.mechanism = {p.mechanism!r} is a MAC (CKF_SIGN, but not "
                                  "a DSTU 4145 signature; SEDO rejects it): use 0x80420031, or "
                                  "leave mechanism out to take the token's own")
        for field in ("module", "key_file", "pin_env", "pin_file", "pin"):
            value = getattr(p, field)
            if value is not None and not isinstance(value, str):
                raise ConfigError(f"{where}.{field} must be a string")
        cfg.keys[p.name] = p

    roles = dict(merged.get("roles", {}))
    # "default" is the base file's placeholder for a machine with no local
    # profiles. Once config_local.toml defines a real profile, the base
    # [roles] pointing at "default" must not keep winning silently: one
    # local profile takes both roles, several need an explicit [roles].
    non_default = [n for n in cfg.keys if n != "default"]
    if roles and not roles_from_local and set(roles.values()) == {"default"} and non_default:
        if len(non_default) > 1:
            raise ConfigError(f"the local config defines several profiles "
                              f"({', '.join(non_default)}): add a [roles] table there")
        roles = {role: non_default[0] for role in ROLES}
    if roles:
        cfg.roles = {}
        for role, target in roles.items():
            if target not in cfg.keys:
                raise ConfigError(f"[roles].{role} = {target!r}: no such [keys.{target}] profile")
            cfg.roles[role] = target
        for role in ROLES:
            # One role given → the other follows it, so a single-key setup
            # needs one line, not two.
            cfg.roles.setdefault(role, next(iter(roles.values())))
    elif len(cfg.keys) == 1:
        only = next(iter(cfg.keys))
        cfg.roles = {role: only for role in ROLES}
    elif set(cfg.roles.values()) - set(cfg.keys):
        raise ConfigError("[roles] is required when several [keys.*] profiles are defined")
    if "default" in cfg.keys and "default" not in cfg.roles.values():
        del cfg.keys["default"]          # placeholder, nothing uses it
    _check_pin_env_collisions(cfg)
    return cfg


def _check_pin_env_collisions(cfg: Config) -> None:
    """
    Two profiles must not read their PIN from one variable.

    The default name keeps only A-Z and 0-9 of the profile name, so "вхід" and
    "підпис" both give SEDO_PIN__, "key-1" and "key.1" both SEDO_PIN_KEY_1.
    One variable holds one value: one of the two tokens would be sent the
    other's PIN, a failed login on every run. Profiles with an explicit
    ``pin_env`` (sharing may be meant) or a ``pin`` in the file are not checked.
    """
    by_env: dict = {}
    for p in cfg.distinct_profiles():
        if p.pin_env is None and not p.pin:
            by_env.setdefault(p.default_pin_env, []).append(p.name)
    for env, names in by_env.items():
        if len(names) > 1:
            raise ConfigError(
                f"profiles {', '.join(names)} would all read their PIN from ${env} "
                "(the default name keeps only A-Z and 0-9 of the profile name): "
                "set pin_env in one of them")


def load_config(client_dir: Optional[Path] = None, local_path: Optional[str] = None,
                env: Optional[dict] = None) -> Config:
    """
    Read config.toml and config_local.toml (both optional), merge, validate,
    apply the SEDO_* environment overrides to the ``auth`` profile.

    ``local_path`` (or $SEDO_CONFIG) replaces config_local.toml and must exist.
    """
    env = os.environ if env is None else env
    client_dir = Path(client_dir) if client_dir is not None else default_config_dir(env)
    base = client_dir / CONFIG_BASE
    local = Path(local_path or env.get(CONFIG_ENV) or (client_dir / CONFIG_LOCAL))
    explicit_local = bool(local_path or env.get(CONFIG_ENV))

    merged: dict = {}
    sources: list = []
    roles_from_local = False
    if base.is_file():
        data = _read_toml(base)
        _validate_raw(data, str(base), is_local=False)
        merged = _deep_merge(merged, data)
        sources.append(base)
    if local.is_file():
        data = _read_toml(local)
        _validate_raw(data, str(local), is_local=True)
        if any("pin" in p for p in data.get("keys", {}).values() if isinstance(p, dict)):
            log.warning("%s stores a PIN in plain text; prefer pin_env or pin_file", local)
        roles_from_local = bool(data.get("roles"))
        merged = _deep_merge(merged, data)
        sources.append(local)
    elif explicit_local:
        raise ConfigError(f"config file not found: {local}")

    cfg = _build(merged, sources, roles_from_local)
    cfg.config_dir = client_dir

    # Environment overrides act on the key that logs in (the single-key
    # setup everyone had before profiles existed). The sign profile follows
    # only when it is the same profile.
    module = env.get("SEDO_MODULE")
    if module:
        cfg.profile("auth").module = module
    return cfg


def _read_pin_file(path: Path) -> str:
    """
    The PIN from a one-line file — exactly what was typed, or ConfigError.

    What reaches C_Login must not be a guess: every wrong PIN costs one of the
    15 attempts of an Almaz-1K, and an unattended run repeats it daily. Windows
    tools add what nobody sees in the editor:

    - a UTF-8 BOM (Notepad, PowerShell 5 ``Set-Content -Encoding UTF8``) became
      the first character of the PIN — a wrong PIN on every run;
    - UTF-16 (PowerShell 5 ``>`` / ``Out-File``) was a UnicodeDecodeError
      traceback; with a BOM it is unambiguous and is simply read;
    - a second line, a NUL or a zero-width character stayed inside the PIN.

    The messages never quote the content.
    """
    raw = path.read_bytes()
    utf16 = raw[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)
    value = None
    try:
        value = raw.decode("utf-16" if utf16 else "utf-8-sig").strip()
    except UnicodeDecodeError:
        pass          # raised below: the exception holds the file's bytes in .object
    if value is None:
        raise ConfigError(f"{path} is not UTF-8 text; save the PIN as one line of UTF-8")
    if len(value.splitlines()) > 1:
        raise ConfigError(f"{path} has more than one line; it must hold the PIN and nothing else")
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise ConfigError(f"{path} has control or invisible characters in the PIN "
                          "(UTF-16 without a BOM? a zero-width character?); "
                          "save the PIN as one line of UTF-8")
    return value


def resolve_profile_pin(profile: KeyProfile, argv_pin: Optional[str] = None,
                        allow_generic_env: bool = True, env: Optional[dict] = None) -> str:
    """
    PIN for one profile: --pin → profile.pin → $<pin_env> → $SEDO_PIN (only when
    allowed) → pin_file → prompt. Empty, or with what nobody types
    (_console.pin_problem) → exit 2 (see _console.read_pin).

    ``allow_generic_env`` is False for a sign profile that differs from the
    auth one: the generic SEDO_PIN belongs to the login key, and sending it to
    another token would spend one of ITS attempts.
    """
    from ._console import PIN_ENV, check_pin, read_pin
    env = os.environ if env is None else env
    # Every source is checked like pin_file (_console.pin_problem): a CR from
    # $(cat file), a space before cmd's &&, a zero-width character → exit 2.
    if argv_pin:
        return check_pin(argv_pin, "--pin")
    if profile.pin:
        log.warning("PIN for profile %r taken from the config file", profile.name)
        return check_pin(profile.pin, f"[keys.{profile.name}].pin")
    env_vars = [profile.effective_pin_env]
    if allow_generic_env:
        env_vars.append(PIN_ENV)
    for var in env_vars:
        value = env.get(var)
        if value:
            return check_pin(value, f"${var}")
    if profile.pin_file:
        path = Path(profile.pin_file).expanduser()
        try:
            mode = path.stat().st_mode
            if os.name != "nt" and mode & (stat.S_IRGRP | stat.S_IROTH):
                log.warning("%s is readable by other users (mode %o)", path, stat.S_IMODE(mode))
            value = _read_pin_file(path)
        except OSError as e:
            raise ConfigError(f"[keys.{profile.name}].pin_file: {e}") from e
        except ConfigError as e:
            raise ConfigError(f"[keys.{profile.name}].pin_file: {e}") from None
        if value:
            return value
        log.warning("%s is empty; asking interactively", path)
    return read_pin(None, prompt=f"PIN ({profile.name}): ", env_vars=())


def redacted(cfg: Config) -> dict:
    """The merged configuration as a plain dict, PINs replaced — for --show-config."""
    out = {
        "config_dir": str(cfg.config_dir) if cfg.config_dir else None,
        "sources": [str(s) for s in cfg.sources],
        "sedo": {"url": cfg.sedo_url, "output": cfg.output, "since": cfg.since},
        "roles": dict(cfg.roles),
        "keys": {},
    }
    for name, p in cfg.keys.items():
        d = {k: v for k, v in dataclasses.asdict(p).items() if k != "name" and v is not None}
        if "pin" in d:
            d["pin"] = "***"
        d.setdefault("pin_env", p.default_pin_env)
        out["keys"][name] = d
    return out
