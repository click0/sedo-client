"""
ansible/playbooks/sedo_daily_linux.yml: how the client is started on a Linux
worker.

The PINs must not go through Ansible's `environment:` there: on a Linux host
Ansible prepends it to the `sh -c` it runs, so the value shows in the `-vvv`
log despite no_log and in `ps` for the whole run. They go on stdin instead and
a small sh wrapper (`pin_exec`) exports them and execs the client.

The tests read the YAML as text, like the other playbook tests: PyYAML is not
a test dependency.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLAYBOOKS = ROOT / "ansible" / "playbooks"
LINUX = PLAYBOOKS / "sedo_daily_linux.yml"


def _text(path=LINUX):
    return path.read_text(encoding="utf-8")


def _folded(text, key):
    """The value of a `key: >-` folded scalar (one paragraph, no blank lines)."""
    m = re.search(rf"^( *){re.escape(key)}: >-\n((?:\1  .*\n)+)", text, re.M)
    assert m, f"{key}: >- not found"
    return " ".join(line.strip() for line in m.group(2).splitlines())


def _tasks(text):
    """(name, body) of every `- name:` item, blocks and plays included."""
    parts = re.split(r"\n(?= *- name: )", text)
    return [(p.strip().split("\n", 1)[0], p) for p in parts if p.lstrip().startswith("- name: ")]


def _run_task(text):
    for name, body in _tasks(text):
        if name == "- name: Run sedo-client with virtual backend":
            return body
    pytest.fail("run task not found")


def _subblock(task, key):
    """The lines of `key:` in a task and those indented under it."""
    m = re.search(rf"^( *){key}:(.*)\n((?:\1 +.*\n?)*)", task, re.M)
    assert m, f"{key}: not in the task"
    return m.group(2) + "\n" + m.group(3)


class TestRunTask:
    def test_environment_carries_nothing_secret(self):
        env = _subblock(_run_task(_text()), "environment")
        assert re.findall(r"^\s+([A-Z_]+):", env, re.M) == ["WINEPREFIX"]
        assert not re.search(r"pin|token|password|secret", env, re.I)

    def test_pins_go_on_stdin_under_no_log(self):
        task = _run_task(_text())
        assert "virtual_pins[inventory_hostname]" in _subblock(task, "vars")
        assert "sedo_pin_env" in _subblock(task, "vars")
        stdin = _subblock(task, "stdin")
        assert "sedo_pins.keys()" in stdin and "join(newline)" in stdin
        assert "no_log: true" in task

    def test_argv_through_the_wrapper_not_a_cmd_string(self):
        # A cmd string goes through shlex.split, which ate the backslashes of
        # 'wine C:\Python312\python.exe' (→ C:Python312python.exe).
        task = _run_task(_text())
        assert "cmd:" not in task and "shell:" not in task
        argv = _subblock(task, "argv")
        assert "['/bin/sh', '-c', pin_exec, 'sh'] + client_python_argv" in argv
        assert "client_script_win" in argv and "virtual_pins" not in argv

    def test_interpreter_string_or_list(self):
        assert "client_python.split()" in _folded(_text(), "client_python_argv")

    def test_no_linux_task_passes_a_secret_through_environment(self):
        for name, body in _tasks(_text()):
            if re.search(r"^ +environment:", body, re.M):
                env = _subblock(body, "environment")
                assert not re.search(r"pin|token|password|secret", env, re.I), name


class TestJinjaLiterals:
    """
    Ansible keeps escapes in a Jinja string literal as typed (2.18 and 2.21
    alike): '\\\\' is two backslashes, '\\n' two characters. In double-quoted
    YAML it was worse: "…replace('/', '\\\\')…" reached Jinja as '\\', an
    unterminated literal, and the Linux run task never got to start the client.
    """

    @pytest.mark.parametrize("path", sorted(PLAYBOOKS.glob("*.yml")), ids=lambda p: p.name)
    def test_no_escape_only_literal_in_templates(self, path):
        for expr in re.findall(r"\{\{.*?\}\}", _text(path), re.S):
            assert not re.search(r"""(['"])(?:\\.)+\1""", expr), f"{path.name}: {expr}"
            assert not re.search(r"""(['"])\\\1""", expr), f"{path.name}: {expr}"

    def test_characters_come_from_yaml(self):
        text = _text()
        assert re.search(r"^    backslash: '\\'$", text, re.M)
        assert re.search(r'^    newline: "\\n"$', text, re.M)
        for var in ("client_script_win", "output_dir_win"):
            line = re.search(rf"^    {var}: (.*)$", text, re.M).group(1)
            assert "replace('/', backslash)" in line, var


PRINT = r"""
import json, os, sys
json.dump({"env": {k: os.environ.get(k) for k in
                   ("SEDO_PIN", "SEDO_PIN_DOC", "SEDO_PIN_LAST", "SEDO_PINX", "LD_PRELOAD", "PATH")},
           "argv": sys.argv[1:], "stdin": sys.stdin.read()}, sys.stdout)
"""


@pytest.mark.skipif(sys.platform == "win32" or not shutil.which("sh"), reason="POSIX sh wrapper")
class TestPinExec:
    """The wrapper itself, run by /bin/sh as the playbook runs it."""

    def _run(self, stdin, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("SEDO_") and k != "LD_PRELOAD"}
        r = subprocess.run(
            ["/bin/sh", "-c", _folded(_text(), "pin_exec"), "sh", sys.executable, "-c", PRINT, *args],
            input=stdin, capture_output=True, text=True, env=env, timeout=30,
        )
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout), env

    def test_exports_the_pins_and_execs_with_argv_intact(self):
        got, env = self._run("SEDO_PIN=1234\nSEDO_PIN_DOC=5 6=7\n",
                             r"C:\Python312\python.exe", "two words", "--since", "2026-11-06")
        assert got["env"]["SEDO_PIN"] == "1234"
        assert got["env"]["SEDO_PIN_DOC"] == "5 6=7"
        assert got["argv"] == [r"C:\Python312\python.exe", "two words", "--since", "2026-11-06"]
        assert got["stdin"] == ""          # the client finds stdin drained, not a stray PIN

    def test_last_line_without_newline(self):
        got, _ = self._run("SEDO_PIN=1\nSEDO_PIN_LAST=99")
        assert got["env"]["SEDO_PIN_LAST"] == "99"

    def test_only_pin_variables_are_exported(self):
        got, env = self._run("PATH=/evil\nLD_PRELOAD=/x.so\nSEDO_PINX=no\nSEDO_PIN=1\n")
        assert got["env"]["PATH"] == env["PATH"]
        assert got["env"]["LD_PRELOAD"] is None and got["env"]["SEDO_PINX"] is None
        assert got["env"]["SEDO_PIN"] == "1"

    def test_pin_is_not_in_the_command_line(self):
        got, _ = self._run("SEDO_PIN=PIN-SECRET-4711\n", "--fetch")
        assert "PIN-SECRET-4711" not in json.dumps(got["argv"])
        assert "PIN-SECRET-4711" not in _folded(_text(), "pin_exec")
