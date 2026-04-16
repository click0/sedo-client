"""
smoke_test.py — швидка перевірка що все працює на Windows worker.
Запускати першим ділом — скаже що треба виправити.
"""

import sys
from pathlib import Path

# Make parent dir importable (коли запущено як scripts/smoke_test.py)
sys.path.insert(0, str(Path(__file__).parent.parent))

TESTS = []

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


@test("iit_client importable")
def t_iit():
    from iit_client import IITClient  # noqa
    return "OK"


@test("pkcs11_signer importable")
def t_pkcs11():
    from pkcs11_signer import PKCS11Signer  # noqa
    return "OK"


@test("sedo_client importable")
def t_sedo():
    from sedo_client import SEDOClient  # noqa
    return "OK"


@test("Windows — SCardSvr running")
def t_scardsvr():
    if sys.platform != "win32":
        return "skipped (not Windows)"
    import subprocess
    r = subprocess.run(["sc", "query", "SCardSvr"], capture_output=True, text=True)
    if "RUNNING" in r.stdout:
        return "RUNNING"
    raise AssertionError("SCardSvr not running")


@test("PKCS11_EKeyAlmaz1C.dll findable")
def t_dll():
    from pkcs11_signer import PKCS11Signer
    try:
        path = PKCS11Signer._find_module()
        size = Path(path).stat().st_size
        return f"{path} ({size} bytes)"
    except FileNotFoundError as e:
        raise AssertionError(str(e))


@test("Windows registry — IIT Sign Agent key")
def t_reg():
    if sys.platform != "win32":
        return "skipped"
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
    passed = failed = 0
    for name, fn in TESTS:
        try:
            result = fn()
            print(f"  ✓ {name:<50} {result}")
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {name:<50} {e}")
            failed += 1
        except Exception as e:
            print(f"  ⚠ {name:<50} {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
