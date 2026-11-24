"""
Shared by every harness in fuzz/: where the code under test is, the budget and
the seed, the list of findings, an HTTP response double and a log trap.

No third-party imports here: the mutation harnesses run on the standard library
(plus what the client itself needs). Hypothesis strategies live in strategies.py.
"""
import atexit
import collections
import logging
import os
import random
import secrets
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"                     # two harnesses borrow builders from the tests
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import sedo  # noqa: E402

# A wheel of an older version in the same environment is found before the
# checkout when a harness is started from another directory — and every finding
# is then about code that is not in the tree any more.
if Path(sedo.__file__).resolve().parent.parent != ROOT:
    sys.exit(f"fuzz: 'sedo' is imported from {sedo.__file__}, not from {ROOT}. "
             "Uninstall the package from this environment or run from the checkout.")

# ── budget and seed ───────────────────────────────────────────────────────────
N = int(os.environ.get("FUZZ_N", "2000"))            # examples per property / cases per harness
_SEED = os.environ.get("FUZZ_SEED")                  # unset: a different run every time
SEED = int(_SEED) if _SEED else random.SystemRandom().randrange(1, 10 ** 6)
SEEDED = _SEED is not None
rnd = random.Random(SEED)                            # the mutation harnesses draw from this

# ── files ─────────────────────────────────────────────────────────────────────
# Everything the code under test and the harnesses create goes to a private
# directory that is removed at exit: runs in parallel do not see each other's
# files, and nothing is ever written into the repository.
_SYSTEM_TMP = tempfile.gettempdir()
TMP = Path(tempfile.mkdtemp(prefix="sedo-fuzz-"))
tempfile.tempdir = str(TMP)
atexit.register(shutil.rmtree, str(TMP), True)

_OUT = None


def out_dir() -> Path:
    """Where reproducers are kept: $FUZZ_OUT, or a new directory that outlives the run."""
    global _OUT
    if _OUT is None:
        _OUT = Path(os.environ.get("FUZZ_OUT") or tempfile.mkdtemp(prefix="sedo-fuzz-out-", dir=_SYSTEM_TMP))
        _OUT.mkdir(parents=True, exist_ok=True)
    return _OUT


def save(name: str, data: bytes) -> Path:
    """Keep the input of a finding; the path is printed with the report."""
    path = out_dir() / name
    path.write_bytes(data)
    return path


# ── findings ──────────────────────────────────────────────────────────────────
FINDINGS = collections.OrderedDict()          # key -> (count, shortest example, its detail)

# The marker PIN, built at run time. Hypothesis harvests string constants from
# the source and feeds them back as "server data": a literal here came back
# inside a generated agent reply and looked like a leak.
PIN = "Pq" + secrets.token_hex(3) + "#zW"


def finding(key, example, detail=""):
    n, ex, d = FINDINGS.get(key, (0, None, None))
    if n == 0 or len(repr(example)) < len(repr(ex)):
        ex, d = example, detail
    FINDINGS[key] = (n + 1, ex, d)


def report(title: str) -> int:
    print(f"\n===== {title}: {len(FINDINGS)} distinct finding(s) =====")
    for key, (n, ex, d) in FINDINGS.items():
        print(f"\n--- {key}  (x{n})")
        print("    example:", repr(ex)[:600])
        if d:
            print("    detail: ", str(d)[:900])
    if _OUT is not None and any(_OUT.iterdir()):
        print(f"\nreproducers: {_OUT}")
    sys.stdout.flush()
    return len(FINDINGS)


def main(title: str, *properties) -> None:
    """Run each property, print what was found; exit 1 on findings, 2 when a harness broke."""
    broken = 0
    for prop in properties:
        try:
            if SEEDED and hasattr(prop, "hypothesis"):
                from hypothesis import seed
                prop = seed(SEED)(prop)
            prop()
        except Exception:                      # a bug in the harness, not a finding: show it
            broken += 1
            traceback.print_exc()
        print(f"done {prop.__name__}", flush=True)
    report(f"{title} (seed {SEED}{'' if SEEDED else ', not fixed'}, budget {N})")
    sys.exit(2 if broken else 1 if FINDINGS else 0)


def tb_key(exc) -> str:
    """'ExcType @ file:line in func' of the innermost frame inside the repository."""
    frames = traceback.extract_tb(exc.__traceback__)
    mine = [f for f in frames if Path(f.filename).resolve().is_relative_to(ROOT)
            and Path(f.filename).resolve().parent != ROOT / "fuzz"]
    f = (mine or frames)[-1]
    return f"{type(exc).__name__} @ {os.path.basename(f.filename)}:{f.lineno} in {f.name}"


def exc_chain_text(exc) -> str:
    """str/repr/args of the exception and of everything reachable from it."""
    seen, out, todo = set(), [], [exc]
    while todo:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        out += [str(e), repr(e), repr(getattr(e, "args", ""))]
        for attr in ("cmd", "output", "stderr", "stdout", "data", "message", "object"):
            if hasattr(e, attr):
                out.append(repr(getattr(e, attr)))
        todo += [e.__cause__, e.__context__]
    return "\n".join(out)


# ── doubles ───────────────────────────────────────────────────────────────────
def response(status=200, body=b"", ctype="application/json", url="https://sedo.mod.gov.ua/x",
             history=()):
    """A real requests.Response: .json(), .text and charset guessing behave as in production."""
    import requests
    r = requests.Response()
    r.status_code = status
    r._content = body if isinstance(body, bytes) else str(body).encode("utf-8", "surrogatepass")
    if ctype is not None:
        r.headers["Content-Type"] = ctype
    r.url = url
    r.history = list(history)
    return r


class LogTrap(logging.Handler):
    """Every record of every logger, formatted — to look for the PIN in."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        try:
            self.lines.append(record.getMessage())
        except Exception as e:                      # a broken log call is a finding too
            self.lines.append(f"<<LOGGING ERROR {type(e).__name__}: {e} | {record.msg!r} {record.args!r}>>")

    def text(self) -> str:
        return "\n".join(self.lines)


def trap_logs() -> LogTrap:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for h in list(root.handlers):
        root.removeHandler(h)
    trap = LogTrap()
    root.addHandler(trap)
    return trap


trap_logs()          # no lastResort handler printing every warning to stderr
