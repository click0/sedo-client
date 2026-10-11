"""
Конфігурація sedo-client: config.toml + config_local.toml, профілі ключів, ролі.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.31
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

import copy
import dataclasses
import logging
import os
import re
import stat
import sys
import tomllib
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

__all__ = [
    "Config", "KeyProfile", "ConfigError", "load_config", "default_config",
    "default_config_dir", "resolve_profile_pin", "redacted",
    "CONFIG_BASE", "CONFIG_LOCAL", "CONFIG_ENV", "ROLES", "BACKENDS",
]

CONFIG_BASE = "config.toml"
CONFIG_LOCAL = "config_local.toml"
# Explicit path of the local file (replaces config_local.toml next to the client).
CONFIG_ENV = "SEDO_CONFIG"

ROLES = ("auth", "sign")
BACKENDS = ("auto", "opensc", "pkcs11", "virtual", "iit_agent")

_SEDO_KEYS = {"url", "output", "since"}
_PROFILE_KEYS = {"backend", "module", "slot", "cert_id", "cert_index", "key_file",
                 "mechanism", "pin_env", "pin_file", "pin"}
_TOP_KEYS = {"sedo", "keys", "roles"}
_HEX_ID_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_MECH_RE = re.compile(r"^0x[0-9A-Fa-f]{1,8}$")


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


def default_config_dir() -> Path:
    """Where config.toml / config_local.toml live: next to the client.

    Development and the documented deployment (git clone → C:\\sedo-client,
    `python sedo_client.py`) put them in the repository root; a PyInstaller
    binary looks next to the .exe.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _read_toml(path: Path) -> dict:
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from e
    except OSError as e:
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
            if not _HEX_ID_RE.match(p.cert_id):
                raise ConfigError(f"{where}.cert_id must be hex bytes like \"01\" or \"0a2b\"")
        if p.mechanism is not None:
            p.mechanism = str(p.mechanism)
            if not _MECH_RE.match(p.mechanism):
                raise ConfigError(f"{where}.mechanism must look like \"0x80420031\"")
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
    return cfg


def load_config(client_dir: Optional[Path] = None, local_path: Optional[str] = None,
                env: Optional[dict] = None) -> Config:
    """
    Read config.toml and config_local.toml (both optional), merge, validate,
    apply the SEDO_* environment overrides to the ``auth`` profile.

    ``local_path`` (or $SEDO_CONFIG) replaces config_local.toml and must exist.
    """
    env = os.environ if env is None else env
    client_dir = Path(client_dir) if client_dir is not None else default_config_dir()
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

    # Environment overrides act on the key that logs in (the single-key
    # setup everyone had before profiles existed). The sign profile follows
    # only when it is the same profile.
    module = env.get("SEDO_MODULE")
    if module:
        cfg.profile("auth").module = module
    return cfg


def resolve_profile_pin(profile: KeyProfile, argv_pin: Optional[str] = None,
                        allow_generic_env: bool = True, env: Optional[dict] = None) -> str:
    """
    PIN for one profile: --pin → profile.pin → $<pin_env> → $SEDO_PIN (only when
    allowed) → pin_file → prompt. Empty → exit 2 (see _console.read_pin).

    ``allow_generic_env`` is False for a sign profile that differs from the
    auth one: the generic SEDO_PIN belongs to the login key, and sending it to
    another token would spend one of ITS attempts.
    """
    from _console import PIN_ENV, read_pin
    env = os.environ if env is None else env
    if argv_pin:
        return argv_pin
    if profile.pin:
        log.warning("PIN for profile %r taken from the config file", profile.name)
        return profile.pin
    env_vars = [profile.effective_pin_env]
    if allow_generic_env:
        env_vars.append(PIN_ENV)
    for var in env_vars:
        value = env.get(var)
        if value:
            return value
    if profile.pin_file:
        path = Path(profile.pin_file).expanduser()
        try:
            mode = path.stat().st_mode
            if os.name != "nt" and mode & (stat.S_IRGRP | stat.S_IROTH):
                log.warning("%s is readable by other users (mode %o)", path, stat.S_IMODE(mode))
            value = path.read_text(encoding="utf-8").strip()
        except OSError as e:
            raise ConfigError(f"[keys.{profile.name}].pin_file: {e}") from e
        if value:
            return value
        log.warning("%s is empty; asking interactively", path)
    return read_pin(None, prompt=f"PIN ({profile.name}): ", env_vars=())


def redacted(cfg: Config) -> dict:
    """The merged configuration as a plain dict, PINs replaced — for --show-config."""
    out = {
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
