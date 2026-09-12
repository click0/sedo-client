"""
Console helpers shared by every CLI entry point of sedo-client.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import sys

__all__ = ["force_utf8_io"]


def force_utf8_io() -> None:
    """
    Ensure stdout/stderr can print emoji and Cyrillic on Windows consoles.

    Ukrainian Windows uses cp866/cp1251 by default, where printing characters
    like ✓ 📄 ❌ raises UnicodeEncodeError and crashes the program. Reconfigure
    the streams to UTF-8 with replacement so output never crashes.

    Single implementation — call it first thing in every ``main()``; do not
    copy the loop inline (it used to live in four places and drifted).
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
