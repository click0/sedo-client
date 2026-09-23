"""
Console helpers shared by every CLI entry point of sedo-client.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import os
import sys
from typing import Optional

__all__ = ["force_utf8_io", "read_pin", "PIN_ENV"]

# Environment variable every CLI accepts instead of --pin (argv is visible in
# the process list; the environment of another user's process is not).
PIN_ENV = "SEDO_PIN"


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


def read_pin(argv_pin: Optional[str], prompt: str = "Token PIN: ") -> str:
    """
    Resolve the token PIN: ``--pin`` → ``$SEDO_PIN`` → interactive prompt.

    An empty result is a hard error, never "carry on without a PIN":

    - Enter at the prompt, or getpass reading EOF from a non-tty, gives "".
      The opensc CLI then silently skipped --sign/--get-cert and exited 0.
    - The PyKCS11 backends would pass "" to C_Login. On Almaz-1K a failed
      C_Login spends one of the 15 attempts before the key is destroyed —
      an empty PIN is a guaranteed failure, so it must never reach the token.

    Raises SystemExit (exit code 2, like an argparse usage error).
    """
    pin = argv_pin or os.environ.get(PIN_ENV)
    if not pin:
        import getpass
        try:
            pin = getpass.getpass(prompt)
        except EOFError:
            pin = ""
    if not pin:
        print(f"❌ Empty PIN — not sending it to the token (a failed login "
              f"spends one of the PIN attempts). Use --pin, ${PIN_ENV} or "
              f"type it at the prompt.", file=sys.stderr)
        raise SystemExit(2)
    return pin
