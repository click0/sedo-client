"""
Build a standalone sedo-client executable with PyInstaller.

Used by the GitHub Actions build workflows (Windows, Linux, FreeBSD).
Handles the fact that backends are imported lazily inside functions —
those modules must be declared as hidden imports or PyInstaller's static
analysis will miss them. PyKCS11 is bundled only if it is installed.

Usage:
    python scripts/build_binary.py
"""

import importlib.util
import subprocess
import sys

# Our own modules imported lazily inside SEDOClient._pick_backend /
# find_sign_mechanism — invisible to PyInstaller static analysis.
HIDDEN_MODULES = [
    "opensc_signer",
    "pkcs11_signer",
    "virtual_signer",
    "iit_client",
    "mechanism_ids",
]


def main() -> int:
    args = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "sedo-client",
        "--clean",
        "--noconfirm",
        "--console",
    ]
    for mod in HIDDEN_MODULES:
        args += ["--hidden-import", mod]

    # Bundle PyKCS11 (pkcs11/virtual backends) only when it is available;
    # the opensc and iit_agent backends work without it.
    if importlib.util.find_spec("PyKCS11") is not None:
        args += ["--hidden-import", "PyKCS11", "--collect-all", "PyKCS11"]
        print("PyKCS11 found — bundling pkcs11/virtual backends.")
    else:
        print("PyKCS11 not installed — building with opensc/iit_agent only.")

    args.append("sedo_client.py")
    print("Running:", " ".join(args))
    return subprocess.call(args)


if __name__ == "__main__":
    sys.exit(main())
