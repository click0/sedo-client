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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The entry point: the package's __main__, which imports sedo.client by its
# absolute name (a relative import has no parent package in a frozen script).
ENTRY = ROOT / "sedo" / "__main__.py"

# Our own modules imported lazily inside SEDOClient._pick_backend /
# find_sign_mechanism — invisible to PyInstaller static analysis.
HIDDEN_MODULES = [
    "sedo._console",
    "sedo.config",
    "sedo.check",
    "sedo.opensc_signer",
    "sedo.pkcs11_signer",
    "sedo.virtual_signer",
    "sedo.iit_client",
    "sedo.mechanism_ids",
]


def main() -> int:
    args = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "sedo-client",
        "--clean",
        "--noconfirm",
        "--console",
        # The repository root, so that the entry's `import sedo` resolves
        # however the script is started.
        "--paths", str(ROOT),
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

    args.append(str(ENTRY))
    print("Running:", " ".join(args))
    return subprocess.call(args)


if __name__ == "__main__":
    sys.exit(main())
