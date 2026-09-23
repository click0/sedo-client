"""
JSON-RPC клієнт до локального EUSignAgent ІІТ "Користувач ЦСК".

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import base64
import binascii
import logging
import re
import sys
from typing import Any, Optional

import requests

log = logging.getLogger(__name__)

__all__ = [
    "IITClient", "IITError", "IITRPCError", "IITAgentNotFound",
    "discover_agent", "verify_agent", "read_port_from_registry",
    "read_trusted_sites", "read_eusigncp_config",
]


# ═══════════════════════════════════════════════════════════════
# Реєстр — знаходження порту агента
# ═══════════════════════════════════════════════════════════════

# Реальний шлях з живої системи IIT "Користувач ЦСК-1"
# Значення HTTPPort/HTTPSPort і інші параметри — у підключі \Common
REGISTRY_PATH = (
    r"SOFTWARE\Institute of Informational Technologies"
    r"\Certificate Authority-1.3\End User\Libraries\Sign Agent\Common"
)

# Підключ з whitelist-ом JS origins (для CORS)
TRUSTED_SITES_PATH = (
    r"SOFTWARE\Institute of Informational Technologies"
    r"\Certificate Authority-1.3\End User\Libraries\Sign Agent\TrustedSites"
)

# Шлях реєстру EUSignCP.dll — конфігурація крипто-бібліотеки (ADDENDUM v5)
EUSIGNCP_REGISTRY_PATH = (
    r"SOFTWARE\Institute of Informational Technologies"
    r"\Certificate Authority-1.3\End User\Libraries\Sign"
)

# Fallback — якщо реєстр недоступний, спробувати звичайні порти
# 8081/8083 — підтверджені порти з реєстру (HTTPPort/HTTPSPort)
FALLBACK_PORTS = [8081, 8083, 9100, 9101, 8080, 8443, 9000, 9090]

# JSON-RPC methods whose params carry a PIN/password — never log their params.
_REDACTED_METHODS = frozenset({
    "ReadPrivateKey", "ReadPrivateKeyBinary", "ReadPrivateKeyFile",
    "ChangePrivateKeyPassword",
})


def _is_loopback(host: str) -> bool:
    """True for 127.0.0.1 / ::1 / localhost — the only hosts where TLS
    verification may be skipped (self-signed agent cert)."""
    import ipaddress
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _as_port(value) -> Optional[int]:
    """
    Registry value → TCP port, or None.

    The installer writes REG_DWORD, but a REG_SZ "8081" comes back as str and
    used to flow as-is into IITClient.port and into "%d" log formats — each
    run printed "--- Logging error --- TypeError: %d format: a real number is
    required, not str", which looks like a crash.
    """
    try:
        if isinstance(value, str):
            text = value.strip().lower()
            port = int(text, 16) if text.startswith("0x") else int(text)
        else:
            port = int(value)
    except (TypeError, ValueError):
        log.warning("Ignoring non-numeric agent port in registry: %r", value)
        return None
    if not 0 < port < 65536:
        log.warning("Ignoring out-of-range agent port in registry: %r", value)
        return None
    return port


def read_port_from_registry() -> tuple[Optional[int], Optional[int]]:
    """
    Читає HTTPPort і HTTPSPort з реєстру.
    Повертає (http_port, https_port). Жоден може бути None.
    Працює тільки на Windows.
    """
    if sys.platform != "win32":
        return None, None

    try:
        import winreg
    except ImportError:
        return None, None

    http_port = https_port = None
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, REGISTRY_PATH, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
                try:
                    http_port = _as_port(winreg.QueryValueEx(key, "HTTPPort")[0])
                except FileNotFoundError:
                    pass
                try:
                    https_port = _as_port(winreg.QueryValueEx(key, "HTTPSPort")[0])
                except FileNotFoundError:
                    pass
                if http_port or https_port:
                    break
        except FileNotFoundError:
            continue
        except OSError as e:
            log.warning("Registry read failed: %s", e)
            continue

    return http_port, https_port


def read_trusted_sites() -> list[str]:
    """Читає список дозволених origins з HKLM\\...\\TrustedSites."""
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []

    sites = []
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, TRUSTED_SITES_PATH, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, i)
                        sites.append(name)
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
        except OSError as e:
            # e.g. PermissionError on a locked-down workstation. The two other
            # registry readers already tolerate it; this one crashed
            # `iit_client.py --discover` right after discovery had succeeded.
            log.warning("Cannot read TrustedSites: %s", e)
            continue
    return sites


def read_eusigncp_config() -> dict:
    """
    Read EUSignCP.dll configuration from the registry.

    Returns a dict with available keys: Path, CertPath, PrivKeyPath, etc.
    Only works on Windows. Returns empty dict otherwise.
    """
    if sys.platform != "win32":
        return {}
    try:
        import winreg
    except ImportError:
        return {}

    config = {}
    value_names = [
        "Path", "CertPath", "PrivKeyPath", "SSLKeyPath", "CACertPath",
    ]
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, EUSIGNCP_REGISTRY_PATH, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
                for name in value_names:
                    try:
                        config[name] = winreg.QueryValueEx(key, name)[0]
                    except FileNotFoundError:
                        pass
                if config:
                    break
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return config


def probe_port(host: str = "127.0.0.1", port: int = 8081,
               timeout: float = 1.0, use_https: bool = False) -> bool:
    """Перевіряє чи відповідає сервер на порту."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/json-rpc"
    # Skip TLS verification only for the self-signed agent cert on loopback.
    skip_verify = use_https and _is_loopback(host)
    try:
        if skip_verify:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass
        # OPTIONS preflight — агент підтримує CORS
        r = requests.options(url, timeout=timeout, verify=not skip_verify)
        return r.status_code in (200, 204, 405)
    except requests.exceptions.RequestException:
        return False


def verify_agent(host: str = "127.0.0.1", port: int = 8081,
                 timeout: float = 2.0, use_https: bool = False) -> bool:
    """
    Підтвердити, що на порту саме JSON-RPC агент ІІТ, а не сторонній сервіс.

    `probe_port` лише перевіряє, що хтось відповідає на OPTIONS. Цього мало:
    у FALLBACK_PORTS є 8080/9000/9090, які часто займають інші застосунки, а
    наступним кроком `IITAgentAdapter.login()` відправляє туди PIN у полі
    `params` методу ReadPrivateKey. Тому перед вибором порту робимо безпечний
    (без PIN) виклик GetVersion і вимагаємо валідний JSON-RPC-конверт.

    `error` у відповіді теж підходить: агент, що не знає GetVersion, поверне
    -32601, і це так само доводить, що це JSON-RPC сервер, а не випадковий HTTP.
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/json-rpc"
    skip_verify = use_https and _is_loopback(host)
    try:
        if skip_verify:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass
        r = requests.post(url, json={"jsonrpc": "2.0", "id": 0,
                                     "method": "GetVersion", "params": []},
                          timeout=timeout, verify=not skip_verify)
        if r.status_code != 200:
            return False
        data = r.json()
    except (requests.exceptions.RequestException, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if "jsonrpc" in data and data.get("jsonrpc") != "2.0":
        return False
    return "result" in data or "error" in data


def discover_agent() -> Optional[tuple[str, int, bool]]:
    """
    Знаходить агента: повертає (host, port, is_https) або None.
    Порядок: 1) реєстр 2) fallback порти.
    """
    http_port, https_port = read_port_from_registry()

    def _found(port: int, https: bool) -> bool:
        # probe_port — дешева перевірка життя; verify_agent — доказ, що це
        # саме агент. Без другої перевірки discovery міг віддати сторонній
        # сервіс на 8080/9000/9090, і PIN пішов би туди (див. verify_agent).
        return (probe_port("127.0.0.1", port, use_https=https)
                and verify_agent("127.0.0.1", port, use_https=https))

    # Спробувати HTTP з реєстру
    if http_port and _found(http_port, False):
        return "127.0.0.1", http_port, False
    # HTTPS з реєстру
    if https_port and _found(https_port, True):
        return "127.0.0.1", https_port, True
    # Fallback порти — пробуємо і HTTP, і HTTPS (8083/8443 — HTTPS-порти агента)
    for p in FALLBACK_PORTS:
        if _found(p, False):
            return "127.0.0.1", p, False
        if _found(p, True):
            return "127.0.0.1", p, True
    return None


# ═══════════════════════════════════════════════════════════════
# Винятки
# ═══════════════════════════════════════════════════════════════

class IITError(Exception):
    """Базова помилка."""


class IITAgentNotFound(IITError):
    """Агент не запущено або порт недоступний."""


class IITRPCError(IITError):
    """Помилка JSON-RPC від сервера."""
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"RPC error {code}: {message}")


# Відомі коди помилок (отримано з аналізу DLL)
# Стандарт JSON-RPC 2.0 + розширення IIT
RPC_ERRORS = {
    -32600: "Invalid request",
    -32601: "Requested method not found",
    -32602: "Invalid method parameters",
    -32603: "Internal rpc error",
    -32700: "Parse error",
    # IIT-specific (якщо вони не переопреділили стандарт)
    1: "Application error (Invalid session)",
    2: "Transport error",
}


_HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
# Keys an agent may wrap the blob in, most specific first.
_SIGNATURE_KEYS = ("signature", "sign", "data", "value", "result")


def _decode_signature(method: str, result: Any, expect_der: bool) -> bytes:
    """
    Normalise whatever the agent returned for a signing call to raw bytes.

    Two defects this replaces:
    - A dict result (``{"signature": "..."}``) was returned as-is, violating
      ``-> bytes``; the caller's base64.b64encode() then raised TypeError,
      which no except clause catches.
    - A hex result was decoded as base64. Every hex digit is in the base64
      alphabet, so that "worked" and produced garbage the server rejects with
      no hint why. The same agent returns certificates as hex, so hex is
      tried first — base64 of DER starts with 'M', never a hex digit, so
      there is no ambiguity for CMS output.

    ``expect_der`` enforces the SEQUENCE tag for CMS SignedData; a raw DSTU
    4145 signature (SignHash) is not DER and is not checked.
    """
    if isinstance(result, dict):
        for key in _SIGNATURE_KEYS:
            value = result.get(key)
            if isinstance(value, (str, bytes, bytearray)) and value:
                result = value
                break
        else:
            raise IITRPCError(
                -1, f"{method} returned an object without a signature field "
                    f"(keys: {sorted(result)})")

    if result is None:
        raise IITRPCError(-1, f"{method} returned empty result")
    if isinstance(result, (bytes, bytearray)):
        blob = bytes(result)
    elif isinstance(result, str):
        text = "".join(result.split())  # MIME-wrapped base64 has newlines
        blob = None
        if _HEX_RE.match(text):
            candidate = bytes.fromhex(text)
            if not expect_der or candidate[:1] == b"\x30":
                blob = candidate
        if blob is None:
            try:
                blob = base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError) as e:
                raise IITRPCError(-1, f"{method} returned invalid base64: {e}") from e
    else:
        raise IITRPCError(
            -1, f"{method} returned unexpected type {type(result).__name__}")

    if not blob:
        raise IITRPCError(-1, f"{method} returned empty result")
    if expect_der and blob[:1] != b"\x30":
        raise IITRPCError(
            -1, f"{method} result is not DER CMS (first byte 0x{blob[0]:02x}); "
                "the agent may use an encoding this client does not know")
    return blob


# ═══════════════════════════════════════════════════════════════
# Клієнт
# ═══════════════════════════════════════════════════════════════

class IITClient:
    """
    JSON-RPC 2.0 клієнт для ІІТ EUSignAgent.

    Приклад:
        client = IITClient.auto_discover()
        client.initialize()
        devices = client.enum_key_media_devices()
        client.read_private_key(devices[0], pin="1234")
        certs = client.enum_own_certificates()
        sig = client.sign_data(b"hello world")
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8081,
                 use_https: bool = False, origin: str = "https://sedo.mod.gov.ua",
                 timeout: float = 30.0):
        self.host = host
        self.port = port
        scheme = "https" if use_https else "http"
        self.base_url = f"{scheme}://{host}:{port}/json-rpc"
        self.origin = origin
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": origin,
            "User-Agent": "sedo-automation/1.0",
        })
        if use_https and _is_loopback(host):
            # Self-signed agent cert on loopback only. For any non-loopback
            # host (e.g. --host remote --https) TLS stays fully verified.
            self.session.verify = False
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass

        self._rpc_id = 0
        self._session_id: Optional[str] = None
        self._initialized = False

    @classmethod
    def auto_discover(cls, **kwargs) -> "IITClient":
        """Знайти агента автоматично."""
        result = discover_agent()
        if result is None:
            raise IITAgentNotFound(
                "EUSignAgent not responding on any known port. "
                "Check that IIT 'Користувач ЦСК' is running and registered in HKLM registry."
            )
        host, port, https = result
        log.info("Found IIT agent at %s://%s:%d",
                 "https" if https else "http", host, port)
        return cls(host=host, port=port, use_https=https, **kwargs)

    # ─── Транспорт ───────────────────────────────────────────

    def call(self, method: str, params: Optional[list] = None) -> Any:
        """Виконати JSON-RPC виклик."""
        self._rpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": method,
            "params": params or [],
        }
        if self._session_id:
            payload["session_id"] = self._session_id

        # Never log params for PIN-carrying methods (would leak the PIN at -v).
        log.debug("→ %s(%s)", method,
                  "[***]" if method in _REDACTED_METHODS else params)
        try:
            r = self.session.post(self.base_url, json=payload, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise IITAgentNotFound(f"Failed to reach agent: {e}") from e

        # The error body is echoed into the exception message, which surfaces at
        # ERROR level — and for a PIN-carrying method that body starts with the
        # request JSON we just sent. _REDACTED_METHODS must gate this too, not
        # only the log.debug above.
        body = "[***]" if method in _REDACTED_METHODS else r.text[:200]

        if r.status_code != 200:
            raise IITRPCError(r.status_code, f"HTTP {r.status_code}: {body}")

        try:
            data = r.json()
        except ValueError as e:
            raise IITRPCError(-1, f"Agent returned non-JSON: {body}") from e

        # Everything below does .get() on the envelope and on "error". A list or
        # a bare string there used to escape as AttributeError — outside every
        # except IITError, so e.g. sign_data's -32601 → "SignData" fallback was
        # unreachable and the whole run died with "'str' object has no
        # attribute 'get'". Normalise to IITRPCError instead.
        if not isinstance(data, dict):
            raise IITRPCError(-1, f"Agent returned non-object JSON ({type(data).__name__})")

        err = data.get("error")
        if err is not None:
            if isinstance(err, dict):
                code = err.get("code", -1)
                message = err.get("message", "Unknown error")
                err_data = err.get("data")
            else:
                code, message, err_data = -1, str(err), None
            try:
                code = int(code)
            except (TypeError, ValueError):
                code = -1
            # An agent that reports the error as a bare string still means
            # "method not found" — keep the -32601 contract callers rely on.
            if code == -1 and "method not found" in str(message).lower():
                code = -32601
            raise IITRPCError(code, str(message), err_data)

        result = data.get("result")

        # IIT extension: agent may return session_id after Initialize.
        # Must be sent back in all subsequent requests (see PROTOCOL-JSON-RPC.md).
        if "session_id" in data and data["session_id"]:
            self._session_id = data["session_id"]

        log.debug("← %s", result)
        return result

    # ─── Життєвий цикл ───────────────────────────────────────

    def initialize(self) -> None:
        """Ініціалізувати бібліотеку. Викликається ПЕРШОЮ."""
        if self._initialized:
            return
        self.call("Initialize")
        # Вимкнути GUI підказки — автоматизація
        try:
            self.call("SetUIMode", [False])
        except IITRPCError:
            pass  # параметри можуть відрізнятись між версіями
        self._initialized = True

    def finalize(self) -> None:
        """Звільнити ресурси. Викликається ОСТАННЬОЮ."""
        # Catch the whole IITError family: call() raises IITAgentNotFound on
        # transport failure, not IITRPCError — a lost agent during teardown
        # must not mask the original error raised from the with-block.
        try:
            self.reset_private_key()
        except IITError as e:
            log.debug("ResetPrivateKey during finalize ignored: %s", e)
        try:
            self.call("Finalize")
        except IITError as e:
            log.debug("Finalize ignored: %s", e)
        self._initialized = False
        self._session_id = None

    def close(self) -> None:
        """
        Закрити HTTP-сесію (пул з'єднань). Викликається після finalize().

        Раніше її не закривав ніхто: довгоживучий воркер, що авторизується
        на кожен прогін, накопичував сокети до агента.
        """
        self.session.close()

    def get_version(self) -> str:
        return self.call("GetVersion")

    # ─── Інформаційні (CLI: iit_client.py --discover) ─────────

    def get_host_info(self) -> dict:
        """Інформація про робочу станцію (OS, архітектура тощо)."""
        return self.call("GetHostInfo")

    # ─── Токен і ключі ───────────────────────────────────────

    def enum_key_media_devices(self) -> list[dict]:
        """
        Перелічити підключені пристрої (Алмази, SecureToken і т.д.).
        Повертає список словників: {devIndex, typeIndex, keyMedia, ...}.
        """
        return self.call("EnumKeyMediaDevices")

    def enum_key_media_types(self) -> list[dict]:
        """Типи носіїв, які підтримує IIT. (CLI: --list-devices)"""
        return self.call("EnumKeyMediaTypes")

    def read_private_key(self, device: dict, pin: str) -> None:
        """
        Прочитати приватний ключ з токена — еквівалент PKCS#11 C_Login.
        Після цього sign() може працювати.

        ⚠️ Алмаз-1К: після 15 невдалих спроб PIN ключ знищується!

        Формат параметрів підтверджений документацією PROTOCOL-JSON-RPC.md:
        [device_dict, pin_string]. device_dict — об'єкт з EnumKeyMediaDevices
        (поля devIndex, typeIndex, keyMedia). Перевірено на прикладах
        із реального JS-віджета ІІТ.
        """
        self.call("ReadPrivateKey", [device, pin])

    def is_private_key_read(self) -> bool:
        """Перевірка чи ключ завантажений. (CLI: діагностика)"""
        return bool(self.call("IsPrivateKeyReaded"))

    def reset_private_key(self) -> None:
        """Забути приватний ключ (logout). Викликається з finalize()."""
        self.call("ResetPrivateKey")

    # ─── Сертифікати ─────────────────────────────────────────

    def enum_own_certificates(self) -> list[dict]:
        """
        Перелік сертифікатів, пов'язаних з відкритим ключем.
        Формат повертаного значення — див. поля subjCN, subjDRFOCode тощо.
        """
        return self.call("EnumOwnCertificates")

    def get_own_certificate(self, index: int) -> dict:
        """Повний сертифікат за індексом (DER + metadata)."""
        return self.call("GetOwnCertificate", [index])

    # ─── Підпис (для авторизації СЕДО) ───────────────────────

    def sign_data(self, data: bytes, options: Optional[dict] = None) -> bytes:
        """
        Підпис CAdES-BES / CAdES-T в залежності від опцій.
        Повертає DER-encoded CMS SignedData.

        Використовується для підпису challenge від СЕДО.
        """
        data_b64 = base64.b64encode(data).decode()
        opts = options or {"internal": True}  # detached = False
        # Method table of EUSignRPC.dll 1.3.1.109 (docs/inventory/exports/
        # EUSignRPC.dll@1.3.1.109-methods.txt) has "Sign" / "SignHash" /
        # "SignFile" — no "SignData" (the dispatcher drops the "Data" suffix:
        # EUSignData → Sign, EUVerifyData → Verify, EUEnvelopData → Envelop).
        # Keep "SignData" as a fallback for older agents that may still expose it.
        method = "Sign"
        try:
            result = self.call(method, [data_b64, opts])
        except IITRPCError as e:
            if e.code != -32601:  # Requested method not found
                raise
            log.info("Agent has no 'Sign' method (%s), retrying as 'SignData'", e.message)
            method = "SignData"
            result = self.call(method, [data_b64, opts])
        # CMS SignedData is DER and must start with a SEQUENCE tag (0x30).
        return _decode_signature(method, result, expect_der=True)

    def sign_hash(self, hash_value: bytes) -> bytes:
        """Raw підпис хешу. (CLI/API: challenge-response де вже є хеш)"""
        h_b64 = base64.b64encode(hash_value).decode()
        result = self.call("SignHash", [h_b64])
        # A raw DSTU 4145 signature is not DER — no 0x30 requirement here.
        return _decode_signature("SignHash", result, expect_der=False)

    # ─── Контекстний менеджер ────────────────────────────────

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, *args):
        try:
            self.finalize()
        finally:
            self.close()
        return False


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def main():
    import argparse
    from _console import force_utf8_io, read_pin
    force_utf8_io()
    parser = argparse.ArgumentParser(description="IIT Agent client")
    parser.add_argument("--discover", action="store_true", help="Find agent and print info")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--https", action="store_true")
    parser.add_argument("--pin", help="Token PIN (or $SEDO_PIN, or the prompt)")
    parser.add_argument("--list-devices", action="store_true")
    parser.add_argument("--list-certs", action="store_true", help="Login and list certificates")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.discover or args.port is None:
        result = discover_agent()
        if result is None:
            print("❌ Agent not found. Is 'Користувач ЦСК' running?")
            sys.exit(1)
        host, port, https = result
        print(f"✓ Found agent: {'https' if https else 'http'}://{host}:{port}")
        print(f"  Trusted sites: {read_trusted_sites()}")
        if not args.list_devices and not args.list_certs:
            return
        client = IITClient(host=host, port=port, use_https=https)
    else:
        client = IITClient(host=args.host, port=args.port, use_https=args.https)

    with client:
        print(f"Version: {client.get_version()}")

        if args.list_devices:
            devices = client.enum_key_media_devices()
            print(f"\n{len(devices)} device(s):")
            for d in devices:
                print(f"  {d}")

        if args.list_certs:
            args.pin = read_pin(args.pin)
            devices = client.enum_key_media_devices()
            if not devices:
                print("No devices found")
                sys.exit(1)
            client.read_private_key(devices[0], args.pin)
            certs = client.enum_own_certificates()
            print(f"\n{len(certs)} certificate(s):")
            for c in certs:
                print(f"  CN={c.get('subjCN')} DRFO={c.get('subjDRFOCode')} "
                      f"EDRPOU={c.get('subjEDRPOUCode')} "
                      f"valid {c.get('certBeginTime')} — {c.get('certEndTime')}")


if __name__ == "__main__":
    main()
