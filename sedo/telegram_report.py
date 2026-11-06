"""
Telegram-звіт щоденного прогону СЕДО: текст із підсумку плейбука і надсилання
через Telegram Bot API.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.33
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026

Лише stdlib: модуль запускається на Linux-контролері Ansible
(``python3 -m sedo.telegram_report`` з кореня репозиторію), де пакетів клієнта
може не бути. Проксі з ``HTTPS_PROXY`` urllib бере сам.

Підсумок (JSON, файл або stdin) збирає play верифікації::

    {"date": "2026-11-06",
     "workers": [{"host": "ws01", "rc": 0, "stdout": "...Документів: 3..."},
                 {"host": "ws02", "rc": null,
                  "error": "Зупинити якщо DLL відсутня: PKCS#11 модуль не знайдено"}],
     "verify": [{"file": "/opt/sedo-reports/ws01/2026-11-06/doc-1.zip", "rc": 0}]}

``rc`` воркера — код виходу sedo-client (null: клієнт не запускався);
``error`` — крок, на якому воркер зупинився, і його повідомлення (rescue у
плейбуку); коли є, показується замість коду;
``rc`` верифікації — код ua-sign-verify (0 валідний, 1 попередження, інше —
помилка), як у task-і «Звіт».

Токен і чат ніколи не йдуть через argv (командний рядок видно в списку
процесів). Плейбук кладе їх у той самий JSON на stdin, ключем
``"telegram": {"bot_token": ..., "chat_id": ...}`` (як у vault.yml), бо
``environment:`` Ansible на Linux дописує перед командою
(``sh -c 'VAR=… python3 …'``) — і токен опинився б у лозі ``-vvv`` попри
``no_log`` та в ``ps``. Для ручного запуску є змінні ``SEDO_TELEGRAM_TOKEN`` /
``SEDO_TELEGRAM_CHAT``; ключ ``telegram`` у stdin має перевагу. Токен не
потрапляє ні у вивід, ні в повідомлення про помилку.

    python3 -m sedo.telegram_report --summary - < summary.json   # telegram key inside
    python3 -m sedo.telegram_report --summary summary.json --dry-run
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path, PurePath
from typing import Callable, Optional

__all__ = ["build_report", "send", "count_documents", "TOKEN_ENV", "CHAT_ENV", "MAX_LEN"]

TELEGRAM_API = "https://api.telegram.org"
TOKEN_ENV = "SEDO_TELEGRAM_TOKEN"
CHAT_ENV = "SEDO_TELEGRAM_CHAT"
MAX_LEN = 4096                      # sendMessage text limit
MAX_ERROR_LINES = 20

# "<bot id>:<secret>", as BotFather issues it. vault.yml.example's placeholder
# ("1234567890:ABCDEF...") does not match, so a copied example is reported
# instead of being sent to Telegram every morning.
_TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}$")
# The line the playbooks' changed_when greps (sedo.client main()).
_DOCS_RE = re.compile(r"Документів:\s*(\d+)")


class ReportError(RuntimeError):
    """Sending failed; the message never contains the token."""


def count_documents(stdout: str) -> Optional[int]:
    """Documents a worker fetched, from sedo-client's "📄 Документів: N", or None."""
    m = _DOCS_RE.search(stdout or "")
    return int(m.group(1)) if m else None


def _short(path: str) -> str:
    """<host>/<date>/<file> — the tail that identifies a document in report_root."""
    return "/".join(PurePath(path).parts[-3:])


def _worker_line(w: dict) -> str:
    host = str(w.get("host", "?"))
    rc = w.get("rc")
    if w.get("error"):
        return f"  ✗ {host}: {' '.join(str(w['error']).split())}"
    if rc is None:
        return f"  – {host}: клієнт не запускався"
    if rc != 0:
        return f"  ✗ {host}: клієнт завершився з кодом {rc}"
    docs = count_documents(w.get("stdout", ""))
    return f"  ✓ {host}: " + (f"документів {docs}" if docs is not None else "без завантаження")


def build_report(summary: dict) -> str:
    """Plain text (no parse_mode: nothing to escape), at most MAX_LEN characters."""
    workers = summary.get("workers") or []
    verify = summary.get("verify") or []
    rcs = [v.get("rc") for v in verify]
    valid, warn = rcs.count(0), rcs.count(1)
    errors = [v for v in verify if v.get("rc") not in (0, 1)]
    failed_workers = [w for w in workers if w.get("rc") != 0 or w.get("error")]

    ok = not errors and not failed_workers
    lines = [f"{'✅' if ok else '⚠️'} СЕДО ЗСУ, щоденний прогін {summary.get('date') or '?'}"]
    if workers:
        lines.append("Воркери:")
        lines += [_worker_line(w) for w in workers]
    lines.append(f"Підписи: усього {len(verify)}, валідних {valid}, "
                 f"з попередженням {warn}, помилок {len(errors)}")
    if errors:
        lines.append("Помилки верифікації:")
        for v in errors[:MAX_ERROR_LINES]:
            lines.append(f"  {_short(str(v.get('file', '?')))} (код {v.get('rc')})")
        if len(errors) > MAX_ERROR_LINES:
            lines.append(f"  … і ще {len(errors) - MAX_ERROR_LINES}")
    text = "\n".join(lines)
    if len(text) > MAX_LEN:
        text = text[:MAX_LEN - 1] + "…"
    return text


def _post_json(url: str, payload: dict, timeout: float) -> tuple:
    """POST JSON → (HTTP status, decoded JSON body or None)."""
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, None


def send(token: str, chat_id: str, text: str, *, api_base: Optional[str] = None,
         timeout: float = 20.0, post: Optional[Callable] = None) -> None:
    """sendMessage, or ReportError with Telegram's description (token redacted).

    There is deliberately no environment variable for the API address: one
    could silently send the bot token to another host.
    """
    api_base = api_base or TELEGRAM_API
    if not _TOKEN_RE.match(token or ""):
        raise ReportError("the bot token does not look like '<digits>:<secret>' "
                          "(vault.yml still holds the example?)")
    if not str(chat_id or "").strip():
        raise ReportError("no chat id")
    url = f"{api_base.rstrip('/')}/bot{token}/sendMessage"
    post = post or _post_json
    try:
        status, body = post(url, {"chat_id": chat_id, "text": text}, timeout)
    except (urllib.error.URLError, OSError) as e:
        raise ReportError(f"Telegram unreachable: {e}".replace(token, "***")) from None
    if status == 200 and isinstance(body, dict) and body.get("ok") is True:
        return
    desc = body.get("description") if isinstance(body, dict) else None
    msg = f"Telegram refused the message: HTTP {status}" + (f", {desc}" if desc else "")
    raise ReportError(msg.replace(token, "***"))


def _read_summary(arg: str) -> dict:
    raw = sys.stdin.read() if arg == "-" else Path(arg).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("the summary must be a JSON object")
    return data


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Send the SEDO daily report to Telegram "
                                             f"(token in ${TOKEN_ENV}, chat in ${CHAT_ENV})")
    ap.add_argument("--summary", required=True, help="summary JSON file, or - for stdin")
    ap.add_argument("--dry-run", action="store_true", help="print the text, send nothing")
    args = ap.parse_args(argv)

    try:
        summary = _read_summary(args.summary)
        creds = summary.pop("telegram", None) or {}
        if not isinstance(creds, dict):
            raise ValueError("'telegram' must be an object with bot_token / chat_id")
        text = build_report(summary)
    except (OSError, ValueError) as e:
        print(f"summary: {e}", file=sys.stderr)
        return 2
    if args.dry_run:
        print(text)
        return 0
    token = str(creds.get("bot_token") or os.environ.get(TOKEN_ENV, ""))
    chat = str(creds.get("chat_id") or os.environ.get(CHAT_ENV, ""))
    if not token or not chat:
        print(f"no credentials: 'telegram' in the summary, or ${TOKEN_ENV} and ${CHAT_ENV} "
              "(or --dry-run)", file=sys.stderr)
        return 2
    try:
        send(token, chat, text)
    except ReportError as e:
        print(f"telegram: {e}", file=sys.stderr)
        return 1
    print("telegram: sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
