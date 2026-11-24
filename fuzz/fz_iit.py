"""Fuzz sedo/iit_client.py and IITAgentAdapter against an agent that answers anything."""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import PIN, exc_chain_text, finding, main, response, tb_key, trap_logs  # noqa: E402
from strategies import JSON, SET, dumps, texts  # noqa: E402
from hypothesis import given, settings, strategies as st  # noqa: E402

import sedo.iit_client as ic  # noqa: E402
from sedo.client import IITAgentAdapter  # noqa: E402

hexs = st.text(alphabet="0123456789abcdefABCDEF", max_size=24)
b64s = st.binary(max_size=18).map(lambda b: base64.b64encode(b).decode())
blobs = st.one_of(hexs, b64s, st.sampled_from(["30", "3082", "MIIB", "MA==", "", " ", "30\n82", "3", "zz",
                                               "MIIB\r\nAAAA", "٣٠"]), texts)
sig_results = st.one_of(JSON, blobs, st.dictionaries(
    st.sampled_from(["signature", "sign", "data", "value", "result", "x"]), st.one_of(JSON, blobs), max_size=3))


@settings(**SET)
@given(sig_results, st.booleans())
def fuzz_decode_signature(result, expect_der):
    try:
        out = ic._decode_signature("Sign", result, expect_der)
    except ic.IITRPCError:
        return
    except Exception as e:
        finding("_decode_signature: " + tb_key(e), result, e)
        return
    if not isinstance(out, bytes) or not out:
        finding("_decode_signature returns empty / non-bytes", result, repr(out))
    elif expect_der and out[:1] != b"\x30":
        finding("_decode_signature(expect_der) returns non-DER", result, repr(out))


errors = st.one_of(JSON, st.fixed_dictionaries({}, optional={
    "code": st.one_of(JSON, st.sampled_from([-32601, "-32601", 1e999, float("nan"), "9" * 5000, [1], True])),
    "message": st.one_of(JSON, st.sampled_from(["Requested method not found", "Method not found", ""])),
    "data": JSON}))
envelopes = st.one_of(JSON, st.fixed_dictionaries({}, optional={
    "jsonrpc": st.sampled_from(["2.0", "1.0", 2, None]), "id": JSON, "result": st.one_of(JSON, sig_results),
    "error": errors, "session_id": JSON}))
http = st.builds(lambda s, b, c: response(s, b, c),
                 st.sampled_from([200, 200, 200, 200, 204, 400, 401, 404, 500]),
                 st.one_of(envelopes.map(dumps), st.binary(max_size=30),
                           st.sampled_from([b"", b"[" * 3000, b'{"error":{"code":1e999}}', b"\xff\xfe"])),
                 st.sampled_from(["application/json", "text/html", None, "application/json; charset=utf-16"]))


class Post:
    """session.post of an agent: replies from a script, then whatever `tail` says."""

    def __init__(self, script, echo=False):
        self.script, self.calls, self.echo = list(script), [], echo

    def __call__(self, url, json=None, timeout=None, **kw):
        self.calls.append(json)
        if not self.script:
            return response(200, b'{"jsonrpc":"2.0","result":null}')
        r = self.script.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _client(script):
    c = ic.IITClient(host="127.0.0.1", port=8081)
    c.session.post = Post(script)
    return c


ALLOWED_CALL = (ic.IITError,)


@settings(**SET)
@given(st.lists(http, min_size=1, max_size=3), st.sampled_from(["GetVersion", "ReadPrivateKey", "Sign"]))
def fuzz_call(script, method):
    c = _client(script)
    trap = trap_logs()
    params = [{"devIndex": 0}, PIN] if method == "ReadPrivateKey" else ["x"]
    try:
        c.call(method, params)
    except ALLOWED_CALL as e:
        if method == "ReadPrivateKey" and PIN in exc_chain_text(e):
            finding("call(ReadPrivateKey): PIN in the exception", str(e))
    except RecursionError:
        finding("call(): RecursionError on deeply nested JSON (not an IITError)", "[[[[…")
    except Exception as e:
        finding("call(): " + tb_key(e), [r.content for r in script], e)
    if method == "ReadPrivateKey" and PIN in trap.text():
        finding("call(ReadPrivateKey): PIN in the log", trap.text()[:300])
    if "LOGGING ERROR" in trap.text():
        finding("call(): broken log call", trap.text()[:300])


@settings(**SET)
@given(st.lists(http, min_size=1, max_size=3), st.binary(max_size=8))
def fuzz_sign(script, data):
    for name in ("sign_data", "sign_hash"):
        c = _client(script)
        try:
            out = getattr(c, name)(data)
        except ALLOWED_CALL:
            continue
        except RecursionError:
            continue
        except Exception as e:
            finding(f"{name}: " + tb_key(e), [r.content for r in script], e)
            continue
        if not isinstance(out, bytes) or not out:
            finding(f"{name} returns empty / non-bytes", [r.content for r in script], repr(out))


def _ok(result):
    return response(200, dumps({"jsonrpc": "2.0", "id": 1, "result": result}))


devices = st.one_of(JSON, st.lists(st.one_of(JSON, st.fixed_dictionaries(
    {"devIndex": st.integers(0, 3), "typeIndex": st.integers(0, 9)})), max_size=3))
certs = st.one_of(JSON, st.lists(JSON, max_size=3))
cert_info = st.one_of(JSON, st.dictionaries(st.sampled_from(["data", "certificate", "x"]),
                                            st.one_of(JSON, blobs), max_size=2))


@settings(**SET)
@given(st.one_of(JSON, st.none()), JSON, devices, JSON, certs, cert_info, sig_results,
       st.integers(0, 3), st.booleans())
def fuzz_adapter(init, uimode, devs, readkey, cert_list, info, signature, cert_index, break_one):
    """login → get_certificate → sign → logout: the calls authorize() makes."""
    script = [_ok(init), _ok(uimode), _ok(devs), _ok(readkey), _ok(cert_list), _ok(info), _ok(signature)]
    c = _client(script)
    adapter = IITAgentAdapter(c, cert_index=cert_index)
    trap = trap_logs()
    try:
        adapter.login(PIN)
        cert = adapter.get_certificate()
        if not isinstance(cert, bytes):
            finding("adapter.get_certificate returns non-bytes", info, repr(cert))
        sig = adapter.sign(b"challenge")
        if not isinstance(sig, bytes) or not sig:
            finding("adapter.sign returns empty / non-bytes", signature, repr(sig))
        if isinstance(cert, bytes) and not cert:
            finding("adapter.login accepts an EMPTY certificate", info)
    except (RuntimeError, ic.IITError) as e:
        if PIN in exc_chain_text(e):
            finding("adapter: PIN in the exception", str(e))
    except Exception as e:
        finding("adapter: " + tb_key(e), {"devices": devs, "certs": cert_list, "info": info}, e)
    try:
        adapter.logout()
        adapter.close()
    except Exception as e:
        finding("adapter.logout/close: " + tb_key(e), None, e)
    if PIN in trap.text():
        lines = [ln for ln in trap.lines if PIN in ln]
        finding("adapter: PIN in the log", lines[0][:300], {"devices": devs, "readkey": readkey})
    if "LOGGING ERROR" in trap.text():
        finding("adapter: broken log call", trap.text()[:300])
    # The PIN may go to the agent in ReadPrivateKey params only.
    for payload in c.session.post.calls:
        if isinstance(payload, dict) and payload.get("method") != "ReadPrivateKey" and PIN in repr(payload):
            finding("adapter: PIN sent in a call other than ReadPrivateKey", payload.get("method"))


echo_text = st.sampled_from(["Invalid method parameters: {p}", "{p}", "bad password '{pin}' for device", "PIN={pin}",
                             "Server error. {req}", "ok"])


@settings(**SET)
@given(st.sampled_from(sorted(ic._REDACTED_METHODS)), echo_text, st.sampled_from(["error", "error_str", "result", "http"]),
       st.sampled_from([200, 400, 500]))
def fuzz_echo(method, template, where, status):
    """An agent that quotes the request back: the PIN must still stay out of logs and exceptions."""
    params = [{"devIndex": 0, "keyMedia": "Almaz"}, PIN] if method != "ChangePrivateKeyPassword" else [PIN, PIN + "new"]
    text = template.format(p=params, pin=PIN, req=dumps({"method": method, "params": params}))
    if where == "error":
        body = dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": text, "data": {"params": params}}})
    elif where == "error_str":
        body = dumps({"jsonrpc": "2.0", "id": 1, "error": text})
    elif where == "result":
        body = dumps({"jsonrpc": "2.0", "id": 1, "result": text})
    else:
        body = text
    c = _client([response(status if where == "http" else 200, body)])
    trap = trap_logs()
    try:
        c.call(method, params)
    except ic.IITError as e:
        if PIN in exc_chain_text(e):
            finding(f"an agent that echoes the request ({where}): PIN in the exception", str(e)[:200])
    except Exception as e:
        finding("call() with an echoing agent: " + tb_key(e), where, e)
    if PIN in trap.text():
        finding(f"an agent that echoes the request ({where}): PIN in the log",
                next(ln for ln in trap.lines if PIN in ln)[:200])


@settings(**SET)
@given(http)
def fuzz_verify_agent(reply):
    old = ic.requests.post
    ic.requests.post = lambda url, **kw: reply
    try:
        out = ic.verify_agent("127.0.0.1", 8081)
        if not isinstance(out, bool):
            finding("verify_agent returns non-bool", reply.content, repr(out))
    except RecursionError:
        finding("verify_agent: RecursionError escapes discovery", "[[[[…")
    except Exception as e:
        finding("verify_agent: " + tb_key(e), reply.content, e)
    finally:
        ic.requests.post = old


urls = st.one_of(texts, st.text(alphabet="htps:/[]@.\\ \n\t%sedo", max_size=24),
                 st.sampled_from(["https://sedo.mod.gov.ua/", " https://sedo.mod.gov.ua/x/ ", "https://[::1",
                                  "https://sedo.mod.gov.ua:abc", "sedo.mod.gov.ua", "", "https://"]))


@settings(**SET)
@given(urls)
def fuzz_origin(url):
    try:
        out = ic.origin_from_url(url)
        assert isinstance(out, str)
    except ValueError:
        pass                       # the URL comes from the operator's config; main() prints the message
    except Exception as e:
        finding("origin_from_url: " + tb_key(e), url, e)


@settings(**SET)
@given(st.one_of(JSON, st.sampled_from(["8081", " 8081 ", "0x1F91", "0x", "65536", "-1", "8081\n", "٨٠٨١", b"8081"])))
def fuzz_as_port(value):
    try:
        out = ic._as_port(value)
        if out is not None and not (isinstance(out, int) and 0 < out < 65536):
            finding("_as_port returns a bad port", value, repr(out))
    except Exception as e:
        finding("_as_port: " + tb_key(e), value, e)
    for fn in (ic._is_loopback,):
        try:
            fn(value if isinstance(value, str) else str(value))
        except Exception as e:
            finding(f"{fn.__name__}: " + tb_key(e), value, e)


if __name__ == "__main__":
    main("sedo/iit_client.py and IITAgentAdapter", fuzz_decode_signature, fuzz_call, fuzz_sign, fuzz_adapter,
         fuzz_echo, fuzz_verify_agent, fuzz_origin, fuzz_as_port)
