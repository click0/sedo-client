"""
JSON-RPC клієнт до локального EUSignAgent ІІТ "Користувач ЦСК".

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.26
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import logging
import sys
from typing import Any, Optional

import requests

log = logging.getLogger(__name__)


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

# Дефолтні порти — підтверджено реальними значеннями з реєстру
DEFAULT_HTTP_PORT = 8081
DEFAULT_HTTPS_PORT = 8083

# Fallback — якщо реєстр недоступний, спробувати звичайні порти
FALLBACK_PORTS = [8081, 8083, 9100, 9101, 8080, 8443, 9000, 9090]


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
                    http_port = winreg.QueryValueEx(key, "HTTPPort")[0]
                except FileNotFoundError:
                    pass
                try:
                    https_port = winreg.QueryValueEx(key, "HTTPSPort")[0]
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


def probe_port(host: str = "127.0.0.1", port: int = 9100,
               timeout: float = 1.0, use_https: bool = False) -> bool:
    """Перевіряє чи відповідає сервер на порту."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/json-rpc"
    try:
        # OPTIONS preflight — агент підтримує CORS
        r = requests.options(url, timeout=timeout, verify=False)
        return r.status_code in (200, 204, 405)
    except requests.exceptions.RequestException:
        return False


def discover_agent() -> Optional[tuple[str, int, bool]]:
    """
    Знаходить агента: повертає (host, port, is_https) або None.
    Порядок: 1) реєстр 2) fallback порти.
    """
    http_port, https_port = read_port_from_registry()

    # Спробувати HTTP з реєстру
    if http_port and probe_port("127.0.0.1", http_port):
        return "127.0.0.1", http_port, False
    # HTTPS з реєстру
    if https_port and probe_port("127.0.0.1", https_port, use_https=True):
        return "127.0.0.1", https_port, True
    # Fallback порти
    for p in FALLBACK_PORTS:
        if probe_port("127.0.0.1", p):
            return "127.0.0.1", p, False
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

    def __init__(self, host: str = "127.0.0.1", port: int = 9100,
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
        if use_https:
            # self-signed cert агента локально на 127.0.0.1 — pinning не потрібен
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

        log.debug("→ %s(%s)", method, params)
        try:
            r = self.session.post(self.base_url, json=payload, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise IITAgentNotFound(f"Failed to reach agent: {e}") from e

        if r.status_code != 200:
            raise IITRPCError(r.status_code, f"HTTP {r.status_code}: {r.text[:200]}")

        try:
            data = r.json()
        except ValueError as e:
            raise IITRPCError(-1, f"Agent returned non-JSON: {r.text[:200]}") from e

        if "error" in data and data["error"] is not None:
            err = data["error"]
            raise IITRPCError(err.get("code", -1),
                              err.get("message", "Unknown error"),
                              err.get("data"))

        result = data.get("result")
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
        try:
            self.call("ResetPrivateKey")
        except IITRPCError:
            pass
        try:
            self.call("Finalize")
        except IITRPCError:
            pass
        self._initialized = False
        self._session_id = None

    def get_version(self) -> str:
        return self.call("GetVersion")

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
        """Типи носіїв, які підтримує IIT."""
        return self.call("EnumKeyMediaTypes")

    def read_private_key(self, device: dict, pin: str) -> None:
        """
        Прочитати приватний ключ з токена — еквівалент PKCS#11 C_Login.
        Після цього sign() може працювати.

        ⚠️ Алмаз-1К: після 15 невдалих спроб PIN ключ знищується!
        """
        # Точний сигнатур: перший параметр — опис пристрою, другий — пароль
        # (Формат уточнюється з реального API dump)
        self.call("ReadPrivateKey", [device, pin])

    def is_private_key_read(self) -> bool:
        return bool(self.call("IsPrivateKeyReaded"))

    def reset_private_key(self) -> None:
        """Забути приватний ключ (logout)."""
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
        import base64
        data_b64 = base64.b64encode(data).decode()
        opts = options or {"internal": True}  # detached = False
        result = self.call("SignData", [data_b64, opts])
        return base64.b64decode(result) if isinstance(result, str) else result

    def sign_hash(self, hash_value: bytes) -> bytes:
        """Raw підпис хешу (для challenge-response де вже є хеш)."""
        import base64
        h_b64 = base64.b64encode(hash_value).decode()
        result = self.call("SignHash", [h_b64])
        return base64.b64decode(result) if isinstance(result, str) else result

    # ─── Контекстний менеджер ────────────────────────────────

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, *args):
        self.finalize()
        return False


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(description="IIT Agent client")
    parser.add_argument("--discover", action="store_true", help="Find agent and print info")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--https", action="store_true")
    parser.add_argument("--pin", help="Token PIN (or prompt)")
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
            if not args.pin:
                import getpass
                args.pin = getpass.getpass("Token PIN: ")
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
