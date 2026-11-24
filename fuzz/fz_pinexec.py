"""
Fuzz the sh wrapper of sedo_daily_linux.yml (pin_exec): whatever the PIN is,
what the client finds in SEDO_PIN is that PIN, byte for byte.

The wrapper text is read from the playbook itself, and it is run by every
shell found here, the way the playbook runs it: PINs as NAME=VALUE lines on
stdin. POSIX only.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import N, TESTS, finding, main, rnd  # noqa: E402

sys.path.insert(0, str(TESTS))
import test_playbook_linux as playbook  # noqa: E402

WRAPPER = playbook._folded(playbook._text(), "pin_exec")
PRINT = "import json,os,sys; json.dump({k: v for k, v in os.environ.items() if k.startswith('SEDO_')}, sys.stdout)"
ALPHABET = "0123456789abcXYZ !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\t" + "éЇ€"
SPECIAL = ["0123", " 1234", "1234 ", "12\\34", "$HOME", "`id`", "a'b", 'a"b', "*", "-n", "\\", "a\\", "#1", "=1=",
           "~", "1\r"]
SHELLS = [s for s in ("/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/busybox") if os.path.exists(s)]


def _pin():
    return rnd.choice(SPECIAL) if rnd.random() < .2 else "".join(rnd.choice(ALPHABET) for _ in range(rnd.randrange(1, 12)))


def fuzz_wrapper():
    if sys.platform == "win32" or not SHELLS:
        print("skipped: no POSIX shell here")
        return
    for _ in range(max(50, N // 10)):                # a process per case and shell
        pins = {"SEDO_PIN": _pin()}
        if rnd.random() < .5:
            pins["SEDO_PIN_DOC"] = _pin()
        stdin = "\n".join(f"{k}={v}" for k, v in pins.items()) + rnd.choice(["\n", ""])
        for shell in SHELLS:
            argv = ([shell, "sh"] if "busybox" in shell else [shell]) + ["-c", WRAPPER, "sh", sys.executable, "-c", PRINT]
            r = subprocess.run(argv, input=stdin.encode(), capture_output=True,
                               env={"PATH": os.environ.get("PATH", "")}, timeout=20)
            try:
                got = json.loads(r.stdout)
            except ValueError:
                finding(f"{shell}: the wrapper failed", pins, r.stderr[:200])
                continue
            if got != pins:
                finding(f"{shell}: the PIN changed on the way to the client", pins, got)


if __name__ == "__main__":
    main("pin_exec, the sh wrapper of sedo_daily_linux.yml", fuzz_wrapper)
