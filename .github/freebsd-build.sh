#!/bin/sh
# Runs INSIDE the FreeBSD VM (build-unix.yml, job build-freebsd). One file for
# both VM attempts of that job, so the retry cannot drift from the first try.
set -e

# FreeBSD has no py311-pip package — bootstrap pip from the stdlib.
python3.11 -m ensurepip --upgrade
python3.11 -m pip install --upgrade pip
python3.11 -m pip install requests pyinstaller pytest setuptools
# PyKCS11 has no FreeBSD wheel. In an isolated build pip fetches its "swig"
# build requirement from PyPI, which compiles SWIG with CMake for about an hour
# and then fails (no bison). Build without isolation instead, against the swig
# that the job's `prepare` installs from pkg.
python3.11 -m pip install --no-build-isolation "PyKCS11>=1.5.15" \
  || echo "PyKCS11 unavailable on FreeBSD — building opensc/iit_agent only"
python3.11 -m pytest tests/ -q
python3.11 scripts/build_binary.py
./dist/sedo-client --help
