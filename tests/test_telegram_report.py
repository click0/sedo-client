"""
sedo.telegram_report: the text built from the playbook summary, sending through
a real local HTTP stand-in of the Bot API (no network), the CLI, and the
contract with both playbooks. The token must never reach any output.
"""

import json
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from sedo import telegram_report as tr

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "1234567890:AAH" + "x" * 32
PLAYBOOKS = {"sedo_daily.yml": "sedo_workers", "sedo_daily_linux.yml": "sedo_workers_linux"}

SUMMARY = {
    "date": "2026-11-06",
    "workers": [
        {"host": "ws01", "rc": 0, "stdout": "✓ Авторизація успішна\n📄 Документів: 3\n"},
        {"host": "ws02", "rc": 1, "stdout": ""},
        {"host": "ws03", "rc": None},
    ],
    "verify": [
        {"file": "/opt/sedo-reports/ws01/2026-11-06/doc-1.zip", "rc": 0},
        {"file": "/opt/sedo-reports/ws01/2026-11-06/doc-2.zip", "rc": 1},
        {"file": "/opt/sedo-reports/ws01/2026-11-06/doc-3.zip", "rc": 2},
    ],
}


class TestBuildReport:
    def test_mixed_run(self):
        text = tr.build_report(SUMMARY)
        assert text.splitlines() == [
            "⚠️ СЕДО ЗСУ, щоденний прогін 2026-11-06",
            "Воркери:",
            "  ✓ ws01: документів 3",
            "  ✗ ws02: клієнт завершився з кодом 1",
            "  – ws03: клієнт не запускався",
            "Підписи: усього 3, валідних 1, з попередженням 1, помилок 1",
            "Помилки верифікації:",
            "  ws01/2026-11-06/doc-3.zip (код 2)",
        ]

    def test_clean_run_is_green(self):
        text = tr.build_report({"date": "2026-11-06",
                                "workers": [{"host": "ws01", "rc": 0, "stdout": "📄 Документів: 0"}],
                                "verify": []})
        assert text.startswith("✅ ")
        assert "документів 0" in text and "помилок 0" in text

    def test_worker_error_from_rescue_wins_over_rc(self):
        text = tr.build_report({"workers": [
            {"host": "ws01", "rc": None,
             "error": "Зупинити якщо DLL відсутня:\n  PKCS#11 модуль не знайдено   на ws01"},
            {"host": "ws02", "rc": 0, "stdout": "📄 Документів: 1", "error": "Fetch на Linux controller: timeout"},
        ]})
        assert "  ✗ ws01: Зупинити якщо DLL відсутня: PKCS#11 модуль не знайдено на ws01" in text
        assert "  ✗ ws02: Fetch на Linux controller: timeout" in text
        assert text.startswith("⚠️ ")

    def test_rc0_without_fetch_line(self):
        assert "без завантаження" in tr.build_report({"workers": [{"host": "w", "rc": 0, "stdout": "✓"}]})

    def test_many_errors_are_capped(self):
        verify = [{"file": f"/r/ws01/d/{i}.zip", "rc": 2} for i in range(25)]
        text = tr.build_report({"verify": verify})
        assert text.count("(код 2)") == tr.MAX_ERROR_LINES
        assert "… і ще 5" in text

    def test_length_limit(self):
        text = tr.build_report({"workers": [{"host": "h" * 300, "rc": 1}] * 30})
        assert len(text) == tr.MAX_LEN and text.endswith("…")

    def test_documents_line_matches_the_client_output(self):
        """count_documents reads the line sedo.client prints and the playbooks grep."""
        src = (ROOT / "sedo" / "client.py").read_text(encoding="utf-8")
        assert 'print(f"📄 Документів: {len(docs)}")' in src
        assert tr.count_documents("📄 Документів: 12") == 12
        assert tr.count_documents("nothing") is None


class _Bot(ThreadingHTTPServer):
    def __init__(self, reply=(200, {"ok": True, "result": {"message_id": 1}})):
        super().__init__(("127.0.0.1", 0), _BotHandler)
        self.url = f"http://127.0.0.1:{self.server_address[1]}"
        self.reply, self.calls = reply, []


class _BotHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.calls.append({"path": self.path, "ctype": self.headers.get("Content-Type"),
                                  "json": json.loads(raw)})
        code, body = self.server.reply
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def bot():
    servers = []

    def start(**kw):
        srv = _Bot(**kw)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        servers.append(srv)
        return srv
    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


class TestSend:
    def test_send_message(self, bot):
        srv = bot()
        tr.send(TOKEN, "@sedo_reports", "привіт", api_base=srv.url)
        assert srv.calls == [{"path": f"/bot{TOKEN}/sendMessage", "ctype": "application/json",
                              "json": {"chat_id": "@sedo_reports", "text": "привіт"}}]

    @pytest.mark.parametrize("reply,expected", [
        ((401, {"ok": False, "error_code": 401, "description": "Unauthorized"}), "HTTP 401, Unauthorized"),
        ((400, {"ok": False, "description": "Bad Request: chat not found"}), "chat not found"),
        ((200, {"ok": False}), "HTTP 200"),
    ])
    def test_refusal_names_the_reason_not_the_token(self, bot, reply, expected):
        srv = bot(reply=reply)
        with pytest.raises(tr.ReportError, match=expected) as e:
            tr.send(TOKEN, "1", "x", api_base=srv.url)
        assert TOKEN not in str(e.value) and TOKEN.split(":")[1] not in str(e.value)

    def test_unreachable(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()                                           # nothing listens there now
        with pytest.raises(tr.ReportError, match="unreachable") as e:
            tr.send(TOKEN, "1", "x", api_base=f"http://127.0.0.1:{port}", timeout=2)
        assert TOKEN not in str(e.value)
        assert e.value.__suppress_context__                 # the URLError chain stays out of tracebacks

    @pytest.mark.parametrize("token", ["1234567890:ABCDEF...", "", "nocolon", "12:short"])
    def test_malformed_token_never_hits_the_network(self, token):
        called = []
        with pytest.raises(tr.ReportError, match="does not look like"):
            tr.send(token, "1", "x", post=lambda *a: called.append(a))
        assert not called

    def test_vault_example_placeholder_is_refused(self):
        text = (ROOT / "ansible" / "inventory" / "vault.yml.example").read_text(encoding="utf-8")
        placeholder = re.search(r'bot_token:\s*"([^"]+)"', text).group(1)
        with pytest.raises(tr.ReportError, match="vault.yml still holds the example"):
            tr.send(placeholder, "@c", "x", post=lambda *a: pytest.fail("network"))

    def test_empty_chat(self):
        with pytest.raises(tr.ReportError, match="no chat id"):
            tr.send(TOKEN, " ", "x", post=lambda *a: pytest.fail("network"))


class TestCLI:
    def _summary(self, tmp_path):
        p = tmp_path / "summary.json"
        p.write_text(json.dumps(SUMMARY, ensure_ascii=False), encoding="utf-8")
        return str(p)

    def test_dry_run_prints_and_sends_nothing(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv(tr.TOKEN_ENV, raising=False)
        assert tr.main(["--summary", self._summary(tmp_path), "--dry-run"]) == 0
        assert capsys.readouterr().out.startswith("⚠️ СЕДО ЗСУ, щоденний прогін 2026-11-06")

    def test_sends_with_env_credentials(self, tmp_path, capsys, monkeypatch, bot):
        srv = bot()
        monkeypatch.setattr(tr, "TELEGRAM_API", srv.url)
        monkeypatch.setenv(tr.TOKEN_ENV, TOKEN)
        monkeypatch.setenv(tr.CHAT_ENV, "-100123")
        assert tr.main(["--summary", self._summary(tmp_path)]) == 0
        out, err = capsys.readouterr()
        assert out.strip() == "telegram: sent" and TOKEN not in out + err
        assert srv.calls[0]["json"]["chat_id"] == "-100123"
        assert srv.calls[0]["json"]["text"] == tr.build_report(SUMMARY)

    def test_refused_send_exits_1_without_the_token(self, tmp_path, capsys, monkeypatch, bot):
        srv = bot(reply=(401, {"ok": False, "description": "Unauthorized"}))
        monkeypatch.setattr(tr, "TELEGRAM_API", srv.url)
        monkeypatch.setenv(tr.TOKEN_ENV, TOKEN)
        monkeypatch.setenv(tr.CHAT_ENV, "1")
        assert tr.main(["--summary", self._summary(tmp_path)]) == 1
        out, err = capsys.readouterr()
        assert "Unauthorized" in err and TOKEN not in out + err

    def test_stdin_summary(self, monkeypatch, capsys):
        import io
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(SUMMARY)))
        assert tr.main(["--summary", "-", "--dry-run"]) == 0
        assert "ws02: клієнт завершився з кодом 1" in capsys.readouterr().out

    def test_stdin_credentials_as_the_playbook_sends_them(self, monkeypatch, capsys, bot):
        """What both playbooks do: summary + {'telegram': vault's dict} on stdin, nothing in env."""
        import io
        srv = bot()
        monkeypatch.setattr(tr, "TELEGRAM_API", srv.url)
        monkeypatch.setenv(tr.TOKEN_ENV, "1111111111:" + "e" * 32)        # stdin wins over env
        monkeypatch.setenv(tr.CHAT_ENV, "env-chat")
        payload = dict(SUMMARY, telegram={"bot_token": TOKEN, "chat_id": "@vault_chat"})
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
        assert tr.main(["--summary", "-"]) == 0
        call = srv.calls[0]
        assert call["path"] == f"/bot{TOKEN}/sendMessage"
        assert call["json"]["chat_id"] == "@vault_chat"
        assert call["json"]["text"] == tr.build_report(SUMMARY)       # credentials not in the text
        out, err = capsys.readouterr()
        assert TOKEN not in out + err

    def test_dry_run_never_prints_stdin_credentials(self, monkeypatch, capsys):
        import io
        payload = dict(SUMMARY, telegram={"bot_token": TOKEN, "chat_id": "@c"})
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
        assert tr.main(["--summary", "-", "--dry-run"]) == 0
        assert TOKEN not in capsys.readouterr().out

    @pytest.mark.parametrize("env", [{}, {"SEDO_TELEGRAM_TOKEN": TOKEN}, {"SEDO_TELEGRAM_CHAT": "1"}])
    def test_missing_credentials_exit_2(self, tmp_path, monkeypatch, capsys, env):
        monkeypatch.delenv(tr.TOKEN_ENV, raising=False)
        monkeypatch.delenv(tr.CHAT_ENV, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        assert tr.main(["--summary", self._summary(tmp_path)]) == 2
        assert "no credentials" in capsys.readouterr().err

    def test_telegram_key_must_be_an_object(self, monkeypatch):
        import io
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(dict(SUMMARY, telegram="x"))))
        assert tr.main(["--summary", "-"]) == 2

    @pytest.mark.parametrize("content", ["not json", "[1, 2]"])
    def test_bad_summary_exit_2(self, tmp_path, content):
        p = tmp_path / "s.json"
        p.write_text(content, encoding="utf-8")
        assert tr.main(["--summary", str(p), "--dry-run"]) == 2

    def test_runs_as_a_module_with_stdlib_only_on_a_cp1252_console(self, tmp_path):
        """
        The controller runs it with plain python3: importing requests would
        break that. cp1252 stands for a Windows console or a C-locale
        controller: printing the Cyrillic + emoji report used to raise
        UnicodeEncodeError there (caught by the Windows CI job).
        """
        import os
        code = ("import sys; sys.modules['requests'] = None; "
                "import runpy; sys.argv = ['x', '--summary', sys.argv[1], '--dry-run']; "
                "runpy.run_module('sedo.telegram_report', run_name='__main__')")
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        r = subprocess.run([sys.executable, "-c", code, self._summary(tmp_path)], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8", env=env)
        assert r.returncode == 0, r.stderr
        assert "⚠️ СЕДО ЗСУ, щоденний прогін 2026-11-06" in r.stdout


class TestPlaybookContract:
    @pytest.fixture(params=sorted(PLAYBOOKS))
    def playbook(self, request):
        return request.param, (ROOT / "ansible" / "playbooks" / request.param).read_text(encoding="utf-8")

    def _task(self, text, marker):
        """The YAML block of the task whose body contains `marker`."""
        for block in re.split(r"\n(?=    - name: )", text):
            if marker in block:
                return block
        pytest.fail(f"no task containing {marker!r}")

    def test_send_task(self, playbook):
        name, text = playbook
        task = self._task(text, "-m sedo.telegram_report")
        assert "--summary -" in task and "stdin:" in task
        # Through stdin, never environment: Ansible prepends environment to the
        # shell command on Linux (sh -c 'VAR=… python3 …') — the -vvv log and ps.
        assert "environment:" not in task
        assert "'telegram': {'bot_token': telegram.bot_token," in task.split("stdin:", 1)[1]
        assert "no_log: true" in task and "failed_when: false" in task
        assert "when: telegram.bot_token | default('') | length > 0" in task

    def test_outcome_task_prints_no_secret(self, playbook):
        _, text = playbook
        task = self._task(text, "telegram_result.stdout")
        assert "telegram.bot_token" not in task and "environment" not in task

    def test_workers_come_from_the_playbook_group(self, playbook):
        name, text = playbook
        task = self._task(text, "report_workers:")
        assert f"groups['{PLAYBOOKS[name]}']" in task

    def test_verify_play_loads_the_vault(self, playbook):
        _, text = playbook
        verify_play = text[text.index("hosts: localhost"):]
        assert "vars_files:\n    - ../inventory/vault.yml" in verify_play.split("tasks:")[0]

    def test_summary_keys_match_the_module(self, playbook):
        _, text = playbook
        task = self._task(text, "-m sedo.telegram_report")
        assert re.search(r"'date':.*'workers':.*'verify':", task, re.S)
        workers = self._task(text, "report_workers:")
        assert "'host': item" in workers and "'error': hostvars[item].sedo_worker_error" in workers
        assert "'file': item.item, 'rc':" in self._task(text, "report_verify:")


class TestPlaybookFailureFlow:
    """A failed worker must not stop the playbook before the verification play."""

    @pytest.fixture(params=sorted(PLAYBOOKS))
    def playbook(self, request):
        return request.param, (ROOT / "ansible" / "playbooks" / request.param).read_text(encoding="utf-8")

    def _plays(self, text):
        return [p for p in re.split(r"\n(?=- name: )", text) if p.startswith("- name: ")]

    def test_worker_play_is_one_block_with_rescue(self, playbook):
        _, text = playbook
        worker = self._plays(text)[0]
        tasks = worker.split("\n  tasks:\n", 1)[1]
        top = re.findall(r"^    - name: (.+)$", tasks, re.M)
        assert len(top) == 1, f"every worker task belongs inside the block, found {top}"
        assert "\n      block:\n" in tasks and "\n      rescue:\n" in tasks
        rescue = tasks.split("\n      rescue:\n", 1)[1]
        assert "sedo_worker_error:" in rescue and "ansible_failed_task.name" in rescue
        assert "ansible.builtin.fail" not in rescue, "re-failing in rescue brings the abort back"

    def test_run_still_fails_at_the_very_end(self, playbook):
        name, text = playbook
        last = re.split(r"\n(?=    - name: )", self._plays(text)[-1].rstrip())[-1]
        assert "ansible.builtin.fail:" in last
        assert f"groups['{PLAYBOOKS[name]}']" in last and "selectattr('sedo_worker_error', 'defined')" in last
