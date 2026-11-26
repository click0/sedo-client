"""Fuzz sedo/telegram_report.py: any summary the playbook could hand over, any reply from Telegram."""
import contextlib
import http.client
import io
import os
import sys
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
from common import N, finding, main, tb_key  # noqa: E402
from strategies import JSON, SET, dumps, mostly, texts  # noqa: E402
from hypothesis import given, settings, strategies as st  # noqa: E402

import sedo.telegram_report as tr  # noqa: E402

# Not a real token: the shape BotFather issues, so that send() accepts it.
TOKEN = "1234567890:AAF_zQx-FUZZtokenFUZZtokenFUZZtoken99"


long_text = st.one_of(texts, st.text(max_size=40), st.sampled_from(["📄 Документів: 3", "Документів: 0", "x" * 400,
                                                                    "📄" * 300, "помилка " * 60, "a\nb\r\nc", "\ud83d"]))
rcs = st.sampled_from([0, 0, 0, 1, 2, None, "0", "1", 0.0, True, False, -1, [0]])
workers = st.lists(mostly(st.fixed_dictionaries({}, optional={
    "host": mostly(st.sampled_from(["ws01", "lin01", "📄" * 40])), "rc": rcs,
    "stdout": mostly(long_text), "error": mostly(st.one_of(st.none(), long_text))})), max_size=25)
verify = st.lists(mostly(st.fixed_dictionaries({}, optional={
    "file": mostly(st.sampled_from(["/opt/sedo-reports/ws01/2026-11-23/doc-1.zip", "x.zip", "", "/", "📄" * 60])),
    "rc": rcs, "crash": mostly(st.booleans())})), max_size=40)
summaries = st.fixed_dictionaries({}, optional={
    "date": mostly(st.just("2026-11-23")), "workers": mostly(workers), "verify": mostly(verify),
    "verifier_missing": mostly(st.one_of(st.none(), st.just("/opt/ua-sign-verify/cli/main.py"))),
    "unverified": mostly(st.integers(0, 9)),
})


def u16(text):
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


@settings(**SET)
@given(summaries)
def fuzz_build(summary):
    try:
        text = tr.build_report(summary)
    except ValueError:
        return                                   # a wrong shape: main() answers "summary: …", exit 2
    except Exception as e:
        finding("build_report: " + tb_key(e), summary, e)
        return
    if not isinstance(text, str) or not text:
        finding("build_report returns empty / non-str", summary)
        return
    if len(text) > tr.MAX_LEN:
        finding("build_report longer than MAX_LEN characters", len(text))
    if u16(text) > tr.MAX_LEN:
        # Telegram counts UTF-16 code units: it answers 400 "message is too long" and the
        # morning report is lost exactly when it is long, i.e. when things went wrong.
        finding("build_report longer than 4096 UTF-16 units (Telegram refuses: message is too long)",
                (len(text), u16(text)))
    # The verdict: a green tick must mean nothing went wrong.
    bad_worker = any(isinstance(w, dict) and (w.get("error") or w.get("rc") != 0)
                     for w in summary.get("workers") or [] if isinstance(summary.get("workers"), list))
    bad_verify = any(isinstance(v, dict) and (v.get("crash") or v.get("rc") not in (0, 1))
                     for v in summary.get("verify") or [] if isinstance(summary.get("verify"), list))
    if text.startswith("✅") and (bad_worker or bad_verify or summary.get("verifier_missing")):
        finding("build_report shows ✅ although something failed", summary, text[:200])


replies = st.one_of(
    st.tuples(st.sampled_from([200, 400, 401, 403, 404, 429, 500]), st.one_of(JSON, st.fixed_dictionaries({}, optional={
        "ok": JSON, "description": st.one_of(JSON, st.just(f"Unauthorized: bot{TOKEN}"))}))),
    st.sampled_from(["urlerror", "oserror", "invalidurl", "httpexc", "valueerror", "timeout"]),
)


def _poster(reply, url_seen):
    def post(url, payload, timeout):
        url_seen.append(url)
        if isinstance(reply, tuple):
            return reply
        if reply == "urlerror":
            raise urllib.error.URLError(f"cannot reach {url}")
        if reply == "oserror":
            raise OSError(f"connect to {url} failed")
        if reply == "timeout":
            raise TimeoutError("timed out")
        if reply == "invalidurl":
            raise http.client.InvalidURL(f"URL can't contain control characters. {url!r}")
        if reply == "httpexc":
            raise http.client.RemoteDisconnected("Remote end closed connection without response")
        raise ValueError(f"bad url {url}")
    return post


@settings(**SET)
@given(replies, st.one_of(st.just("12345"), st.just(-100123), texts), st.text(max_size=20))
def fuzz_send(reply, chat, text):
    seen = []
    try:
        tr.send(TOKEN, chat, text, post=_poster(reply, seen))
    except tr.ReportError as e:
        if TOKEN in str(e) or TOKEN in repr(e.__cause__) or TOKEN in repr(e.__context__):
            finding("send(): bot token reachable from ReportError", reply, str(e))
    except Exception as e:
        leak = " — AND the message carries the bot token" if TOKEN in str(e) else ""
        finding("send(): " + type(e).__name__ + " is not turned into ReportError" + leak, reply, e)


tokens = st.one_of(st.just(TOKEN), st.sampled_from([TOKEN + "\n", TOKEN + "\r\n", " " + TOKEN, TOKEN + " ",
                                                    "﻿" + TOKEN, "١٢٣٤٥٦:" + "A" * 35, "12345:" + "é" * 30, ""]),
                   texts)


@settings(**{**SET, "max_examples": max(300, N // 3)})
@given(mostly(summaries), mostly(st.fixed_dictionaries({}, optional={"bot_token": mostly(tokens, odds=2),
                                                                      "chat_id": mostly(st.just("123"))})),
       st.booleans())
def fuzz_main(summary, creds, dry):
    """The real main() with the real urllib, pointed at a closed local port: no network."""
    doc = dict(summary) if isinstance(summary, dict) else summary
    if isinstance(doc, dict):
        doc["telegram"] = creds
    old_in, old_api = sys.stdin, tr.TELEGRAM_API
    tr.TELEGRAM_API = "http://127.0.0.1:9"                 # discard port: connection refused
    sys.stdin = io.StringIO(dumps(doc))
    out, err = io.StringIO(), io.StringIO()
    code = None
    env_before = dict(os.environ)
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", tr.TOKEN_ENV, tr.CHAT_ENV):
        os.environ.pop(var, None)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = tr.main(["--summary", "-"] + (["--dry-run"] if dry else []))
    except SystemExit as e:
        code = e.code
    except BaseException as e:
        import traceback
        shown = "".join(traceback.format_exception(e))
        leak = " — AND the traceback shows the bot token" if TOKEN in shown else ""
        finding("telegram_report.main(): uncaught " + tb_key(e) + leak,
                {"token": creds.get("bot_token") if isinstance(creds, dict) else creds}, e)
    finally:
        sys.stdin, tr.TELEGRAM_API = old_in, old_api
        os.environ.clear()
        os.environ.update(env_before)
    if TOKEN in out.getvalue() + err.getvalue():
        finding("telegram_report.main(): bot token in stdout/stderr", err.getvalue()[:300])
    if code not in (0, 1, 2, None):
        finding(f"telegram_report.main(): exit code {code!r}", None)


if __name__ == "__main__":
    main("sedo/telegram_report.py", fuzz_build, fuzz_send, fuzz_main)
