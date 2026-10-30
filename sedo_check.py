"""
Compatibility shim: this module moved to sedo.check.

Imported, it warns (DeprecationWarning) and hands back sedo.check itself.
"""

import importlib as _importlib
import sys as _sys
import warnings as _warnings

_warnings.warn(
    "top-level module 'sedo_check' is deprecated; use 'sedo.check' instead",
    DeprecationWarning,
    stacklevel=2,
)
# The module itself, not a copy: every name (the underscored ones too) and
# every monkeypatch reach the real module.
_sys.modules[__name__] = _importlib.import_module("sedo.check")
