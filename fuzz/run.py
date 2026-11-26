"""
Run the fuzz harnesses of this directory and say what they found.

    python fuzz/run.py                      every harness, default budget
    python fuzz/run.py client iit -n 5000   two of them, 5000 examples per property
    python fuzz/run.py --seed 7 fiddler     the same run again
    python fuzz/run.py -j 4                 four harnesses at a time
    python fuzz/run.py --list

Each harness lives in its own directory, fuzz/<name>/fz_<name>.py, and is a
separate process (it runs on its own too); fuzz/shared/ holds what they share.
Exit code: 0 nothing found, 1 findings, 2 a harness itself failed.
"""
import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# name → what is fed to what. fuzz/README.md has the properties.
HARNESSES = {
    "client": "SEDO responses, 'next' links, document ids, the whole CLI → sedo/client.py",
    "iit": "IIT agent replies, an agent that quotes the request → sedo/iit_client.py",
    "opensc": "pkcs11-tool output, exit codes and files → sedo/opensc_signer.py",
    "config": "config files and PIN files as editors save them → sedo/config.py",
    "report": "summaries, bot tokens, transport errors → sedo/telegram_report.py",
    "pe": "mutated PE images → sedo/check.py, scripts/iit_inventory.py",
    "fiddler": "captures with a marked value in every position → scripts/fiddler_analyze.py",
    "pinexec": "random PINs through the sh wrapper of sedo_daily_linux.yml",
    "ansible": "vault PINs and config_local.toml.j2 through ansible-playbook",
}


def run_one(name: str, env: dict, out: Path, timeout: int) -> tuple:
    started = time.monotonic()
    try:
        r = subprocess.run([sys.executable, str(HERE / name / f"fz_{name}.py")], env=env, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout)
        code, text = r.returncode, r.stdout + r.stderr
        # A harness that dies on import also exits 1: findings are only what a report lists.
        if code not in (0, 2) and "distinct finding(s) =====" not in text:
            code = 2
    except subprocess.TimeoutExpired as e:
        code, text = 2, f"{e.stdout or ''}{e.stderr or ''}\ntimed out after {timeout} s"
    (out / f"{name}.log").write_text(text, encoding="utf-8")
    return name, code, text, time.monotonic() - started


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fuzz the code of sedo-client that reads what it did not write.")
    ap.add_argument("names", nargs="*", metavar="NAME", help=f"harnesses to run (default: all): {', '.join(HARNESSES)}")
    ap.add_argument("-n", "--budget", type=int, help="examples per property / cases per harness (default 2000)")
    ap.add_argument("--seed", type=int, help="repeat a run: the seed a report printed")
    ap.add_argument("-j", "--jobs", type=int, default=1, help="harnesses to run at a time (default 1)")
    ap.add_argument("--out", help="directory for logs and reproducers (default: a temp dir, kept only on findings)")
    ap.add_argument("--timeout", type=int, default=3600, help="seconds per harness (default 3600)")
    ap.add_argument("--list", action="store_true", help="list the harnesses and exit")
    args = ap.parse_args(argv)
    if args.list:
        for name, what in HARNESSES.items():
            print(f"{name:8} {what}")
        return 0
    unknown = [n for n in args.names if n not in HARNESSES]
    if unknown:
        ap.error(f"unknown harness: {', '.join(unknown)} (see --list)")

    out = Path(args.out or tempfile.mkdtemp(prefix="sedo-fuzz-out-"))
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, FUZZ_OUT=str(out), PYTHONIOENCODING="utf-8")
    if args.budget:
        env["FUZZ_N"] = str(args.budget)
    if args.seed is not None:
        env["FUZZ_SEED"] = str(args.seed)

    names = args.names or list(HARNESSES)
    worst = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for name, code, text, seconds in pool.map(lambda n: run_one(n, env, out, args.timeout), names):
            state = {0: "ok", 1: "FINDINGS"}.get(code, "HARNESS FAILED")
            if code == 0 and "skipped:" in text:
                state = "skipped"
            print(f"{name:8} {state:14} {seconds:6.0f} s", flush=True)
            if code == 1:                                  # the report, from its "=====" line on
                print(text[text.find("\n====="):].rstrip() + "\n")
            elif code != 0:
                print(text[-3000:].rstrip() + "\n")
            elif state == "skipped":
                print("         " + next(ln for ln in text.splitlines() if "skipped:" in ln))
            worst = max(worst, code if code in (0, 1) else 2)
    if worst or args.out:
        print(f"logs and reproducers: {out}")
    else:
        shutil.rmtree(out, ignore_errors=True)
    return worst


if __name__ == "__main__":
    sys.exit(main())
