"""
smoke_test.py — швидка перевірка що все працює на Windows worker.
Запускати першим ділом — скаже що треба виправити.

Код виходу 1 лише при ✗ / ⚠. Перевірки, які на цій ОС не мають сенсу
(служба SCardSvr, реєстр, автопошук DLL поза Windows), позначаються «–» і
рахуються як пропущені, а не як провал.
"""

import sys
from pathlib import Path

# Make parent dir importable (коли запущено як scripts/smoke_test.py)
sys.path.insert(0, str(Path(__file__).parent.parent))

TESTS = []


class Skip(Exception):
    """The check does not apply here; the message says why."""


def test(name):
    def wrap(fn):
        TESTS.append((name, fn))
        return fn
    return wrap


@test("Python version >= 3.11")
def t_python():
    assert sys.version_info >= (3, 11), f"Python {sys.version_info} too old"
    return f"Python {sys.version.split()[0]}"


@test("PyKCS11 installed")
def t_pykcs11():
    try:
        import PyKCS11
        return f"PyKCS11 {getattr(PyKCS11, '__version__', '?')}"
    except ImportError:
        raise AssertionError("pip install PyKCS11")


@test("requests installed")
def t_requests():
    import requests
    return f"requests {requests.__version__}"


@test("sedo.iit_client importable")
def t_iit():
    from sedo.iit_client import IITClient  # noqa
    return "OK"


@test("sedo.pkcs11_signer importable")
def t_pkcs11():
    from sedo.pkcs11_signer import PKCS11Signer  # noqa
    return "OK"


@test("sedo.client importable")
def t_sedo():
    from sedo.client import SEDOClient  # noqa
    return "OK"


@test("Windows — SCardSvr running")
def t_scardsvr():
    if sys.platform != "win32":
        raise Skip("not Windows")
    import subprocess
    r = subprocess.run(["sc", "query", "SCardSvr"], capture_output=True, text=True,
                        timeout=10)
    if "RUNNING" in r.stdout:
        return "RUNNING"
    raise AssertionError("SCardSvr not running")


@test("PKCS#11 module (PKCS11.EKeyAlmaz1C.dll / Av337CryptokiD.dll)")
def t_dll():
    """
    $SEDO_MODULE is checked on any OS: whoever set it means that file. The
    built-in search only knows Windows paths of the IIT/Avest DLLs, so a miss
    outside Windows (a Linux controller, CI) is a skip, not a failure; under
    Wine, Python reports win32 and the search runs as on Windows.
    """
    from sedo._console import module_from_env
    from sedo.pkcs11_signer import PKCS11Signer
    explicit = module_from_env(None)
    if explicit:
        if not Path(explicit).is_file():
            raise AssertionError(f"$SEDO_MODULE does not exist: {explicit}")
        path = explicit
    else:
        try:
            path = PKCS11Signer._find_module()
        except FileNotFoundError as e:
            if sys.platform != "win32":
                raise Skip("not Windows and $SEDO_MODULE unset")
            raise AssertionError(str(e))
    return f"{path} ({Path(path).stat().st_size} bytes)"


@test("Windows registry — IIT Sign Agent key")
def t_reg():
    if sys.platform != "win32":
        raise Skip("not Windows")
    try:
        import winreg
        path = (r"SOFTWARE\Institute of Informational Technologies"
                r"\Certificate Authority-1.3\End User\Libraries\Sign Agent")
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, path, 0,
                                    winreg.KEY_READ | winreg.KEY_WOW64_32KEY):
                    return "found"
            except FileNotFoundError:
                continue
        raise AssertionError("Registry key not found")
    except ImportError:
        raise AssertionError("winreg unavailable")


def main():
    # UTF-8 stdout/stderr so emoji (✓ ✗ ⚠) don't crash on Windows cp1251/cp866.
    from sedo._console import force_utf8_io
    force_utf8_io()

    passed = failed = skipped = 0
    w = max(len(name) for name, _ in TESTS)
    for name, fn in TESTS:
        try:
            result = fn()
            print(f"  ✓ {name:<{w}} {result}")
            passed += 1
        except Skip as e:
            print(f"  – {name:<{w}} skipped ({e})")
            skipped += 1
        except AssertionError as e:
            print(f"  ✗ {name:<{w}} {e}")
            failed += 1
        except Exception as e:
            print(f"  ⚠ {name:<{w}} {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {skipped} skipped, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
