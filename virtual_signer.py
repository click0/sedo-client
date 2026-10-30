"""
Compatibility shim: this module moved to sedo.virtual_signer.

Imported, it warns (DeprecationWarning) and hands back sedo.virtual_signer itself.
"""

import importlib as _importlib
import sys as _sys
import warnings as _warnings

_warnings.warn(
    "top-level module 'virtual_signer' is deprecated; use 'sedo.virtual_signer' instead",
    DeprecationWarning,
    stacklevel=2,
)
# The module itself, not a copy: every name (the underscored ones too) and
# every monkeypatch reach the real module.
_sys.modules[__name__] = _importlib.import_module("sedo.virtual_signer")
