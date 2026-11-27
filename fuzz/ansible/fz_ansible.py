"""
Fuzz what passes through Ansible itself, with the ansible-playbook found on
PATH (or named in $ANSIBLE_PLAYBOOK). Skipped when there is none.

1. PINs in vault.yml. YAML retypes a value written without quotes: 0123 is the
   number 83, 12_34 is 1234, an empty value is None. For every generated PIN,
   quoted and not: either the playbooks' own guard refuses it, or what the
   client would receive is the PIN exactly as typed. A quoted PIN is never
   refused.
2. config_local.toml.j2. Random sedo_keys / sedo_roles are rendered by the
   real template and read back by load_config: every profile and field as it
   was given, or the ConfigError about two profiles sharing one PIN variable.

The guard and stdin expressions are cut out of the playbooks and the template
is used in place: what is fuzzed is what is deployed, not a copy of it.
"""
import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
from common import N, ROOT, TESTS, finding, main, rnd  # noqa: E402

import sedo.config as cfg  # noqa: E402

sys.path.insert(0, str(TESTS))
import test_playbook_linux as playbook  # noqa: E402

ANSIBLE = os.environ.get("ANSIBLE_PLAYBOOK") or shutil.which("ansible-playbook")
TEMPLATE = ROOT / "ansible" / "playbooks" / "templates" / "config_local.toml.j2"


def _ansible(play: Path, out: Path) -> None:
    env = dict(os.environ, ANSIBLE_LOCALHOST_WARNING="False", ANSIBLE_INVENTORY_UNPARSED_WARNING="False",
               ANSIBLE_NOCOLOR="1", ANSIBLE_RETRY_FILES_ENABLED="False")
    r = subprocess.run([ANSIBLE, str(play), "-e", f"out={out}"], cwd=play.parent, env=env,
                       capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError(f"ansible-playbook failed ({r.returncode}):\n{(r.stdout + r.stderr)[-2500:]}")


# ── 1. PINs in vault.yml ──────────────────────────────────────────────────────
# Only what YAML accepts as a plain scalar: a PIN that breaks the file stops
# the whole run before any client starts, which is safe and not the subject.
PLAIN = ["0", "0000", "0123", "001234", "0777", "0999", "1234", "12_34", "1_000", "0x10", "0o17", "0b11", "1e3",
         "1.50", ".5", "1.", "+123", "-12", "1:30", "12:30:45", "yes", "no", "on", "off", "true", "False", "null",
         "~", "NULL", "y", "n", ".inf", ".nan", "2026-11-24", "12ab", "ab12", "1234567890123456789012", "00"]


def _pins() -> dict:
    """{case name: (text in the YAML file, the PIN the operator meant)}"""
    cases = {}
    values = list(PLAIN)
    for _ in range(max(40, N // 25)):
        digits = "".join(rnd.choice("0123456789") for _ in range(rnd.randrange(3, 9)))
        values.append(("0" * rnd.randrange(0, 3) + digits) if rnd.random() < .5 else digits)
        if rnd.random() < .2:
            values.append(digits[:2] + rnd.choice("_.:+-exob") + digits[2:])
    for i, pin in enumerate(values):
        cases[f"plain{i}"] = (pin, pin)
        cases[f"quoted{i}"] = (json.dumps(pin), pin)
    for i in range(20):                                   # anything goes inside quotes, Jinja braces aside
        pin = "".join(rnd.choice("0123456789abcXYZ !#$&'()*+,-./:;<=>?@[\\]^_`|~\tЇ€") for _ in range(rnd.randrange(1, 12)))
        cases[f"quotedany{i}"] = (json.dumps(pin, ensure_ascii=False), pin)
    return cases


def fuzz_vault_pins():
    if not ANSIBLE:
        print("skipped: ansible-playbook not found (pip install ansible-core, or set ANSIBLE_PLAYBOOK)")
        return
    work = Path(tempfile.mkdtemp(prefix="pins-"))
    cases = _pins()
    (work / "vault.yml").write_text(
        "pins:\n" + "".join(f"  {name}: {text}\n" for name, (text, _) in cases.items()), encoding="utf-8")
    plays = {"sedo_daily_linux.yml": playbook._text(playbook.LINUX), "sedo_daily.yml": playbook._text(playbook.WINDOWS)}
    # sedo_pins is built inside the same template as each expression, and the
    # loop runs over the case NAMES. ansible-core <= 2.18 turns the result of
    # a template into text and back with ast.literal_eval: a dict holding the
    # float inf/nan (.inf, .nan) or a date (2026-11-24) does not come back,
    # and "loop: {{ pins | dict2items }}" failed with "Invalid data passed to
    # 'loop'" before a single case ran. In the playbooks sedo_pins comes from
    # vault.yml as it is, without that round trip.
    own_pins = "{% set sedo_pins = {'SEDO_PIN': pins[item]} %}"
    tasks = []
    for name, text in plays.items():
        guard = playbook._folded(text, "pins_not_text")
        # Linux: NAME=VALUE lines on stdin. Windows: the value becomes an environment variable.
        arrives = playbook._folded(text, "stdin") if "linux" in name else "{{ 'SEDO_PIN=' ~ sedo_pins.SEDO_PIN }}"
        assert "sedo_pins" in arrives and "rejectattr" in guard, name
        assert "{%" not in guard + arrives, name
        key = name.split(".")[0]
        tasks.append(f"""
    - name: Each PIN through the expressions of {name}
      ansible.builtin.set_fact:
        {key}: "{{{{ {key} | default({{}}) | combine({{item: {{'refused': refused, 'arrives': arrives}}}}) }}}}"
      vars:
        pins_not_text: >-
          {own_pins}{guard}
        refused: "{{{{ pins_not_text | length > 0 }}}}"
        arrives: >-
          {own_pins}{arrives}
      loop: "{{{{ pins | list }}}}"
""")
    keys = [name.split(".")[0] for name in plays]
    everything = ", ".join(f"'{k}': {k}" for k in keys)
    (work / "play.yml").write_text(f"""- name: Vault PINs through the playbooks' own expressions
  hosts: localhost
  gather_facts: false
  vars_files: [vault.yml]
  vars:
    newline: "\\n"
  tasks:{''.join(tasks)}
    - name: Save what was seen
      ansible.builtin.copy:
        content: "{{{{ {{{everything}}} | to_json }}}}"
        dest: "{{{{ out }}}}/pins.json"
        mode: "0600"
""", encoding="utf-8")
    _ansible(work / "play.yml", work)
    seen = json.loads((work / "pins.json").read_text(encoding="utf-8"))
    for key, results in seen.items():
        for name, (text, pin) in cases.items():
            got = results[name]
            refused = got["refused"] in (True, "True")
            if name.startswith("quoted") and refused:
                finding(f"{key}: a QUOTED PIN is refused by the guard", text)
            elif not refused and got["arrives"] != f"SEDO_PIN={pin}":
                finding(f"{key}: the client would get a PIN that is not the one in vault.yml",
                        f"vault.yml: {text}", f"arrives as {got['arrives']!r}")


# ── 2. the config template ────────────────────────────────────────────────────
NAMES = ["login", "doc", "вхід", "підпис", "my key", "a.b", "key-1", "key.1", "Login", 'k"q', "k'q", "ключ №1",
         "x]y", "a#b", "1", "", " ", "a\\b", "ї", "= x", "[z]"]
PATHS = ["C:\\Program Files (x86)\\Institute of Informational Technologies\\EKeys\\Almaz1C\\PKCS11.EKeyAlmaz1C.dll",
         "C:\\libs\\Користувач ЦСК\\a.dll", "C:\\new\\table\\x.dll", "/opt/it's/a \"b\".so", "C:\\dir with #hash\\a.dll",
         "Z:\\tmp\\юзер\\Key-6.dat", "C:\\a\\\\b", "'''", '"""', "C:\\ends-with-backslash\\", "a\tb", "📄.dll",
         "a\nb", "", "\\u0041", "%TEMP%\\a.dll", "$HOME/a.so"]


def _profiles(i: int) -> dict:
    keys = {}
    for name in rnd.sample(NAMES, rnd.randrange(1, 3)):
        prof = {"backend": rnd.choice(["opensc", "pkcs11", "virtual", "iit_agent"])}
        for field, odds, value in (("module", .8, rnd.choice(PATHS)), ("key_file", .3, rnd.choice(PATHS)),
                                   ("cert_id", .3, rnd.choice(["01", "0a2b"])), ("slot", .3, rnd.randrange(0, 3)),
                                   ("cert_index", .2, rnd.randrange(0, 3)), ("mechanism", .2, "0x80420031"),
                                   ("pin_env", .2, f"MY_PIN_{i}")):
            if rnd.random() < odds:
                prof[field] = value
        keys[name] = prof
    names = list(keys)
    return {"sedo_keys": keys, "sedo_roles": {"auth": names[0], "sign": names[-1]}}


def fuzz_config_template():
    if not ANSIBLE:
        print("skipped: ansible-playbook not found (pip install ansible-core, or set ANSIBLE_PLAYBOOK)")
        return
    work = Path(tempfile.mkdtemp(prefix="template-"))
    (work / "out").mkdir()
    cases = [_profiles(i) for i in range(min(300, max(30, N // 15)))]
    (work / "cases.json").write_text(json.dumps({"cases": cases}, ensure_ascii=False), encoding="utf-8")
    template = json.dumps(str(TEMPLATE))
    (work / "play.yml").write_text(f"""- name: config_local.toml from random inventories
  hosts: localhost
  gather_facts: false
  vars_files: [cases.json]
  tasks:
    - name: Render the template the playbooks deploy
      ansible.builtin.template:
        src: {template}
        dest: "{{{{ out }}}}/out/{{{{ idx }}}}.toml"
        mode: "0600"
      vars:
        sedo_keys: "{{{{ item.sedo_keys }}}}"
        sedo_roles: "{{{{ item.sedo_roles }}}}"
      loop: "{{{{ cases }}}}"
      loop_control:
        index_var: idx
        label: "{{{{ idx }}}}"
""", encoding="utf-8")
    _ansible(work / "play.yml", work)
    for i, case in enumerate(cases):
        want = case["sedo_keys"]
        d = Path(tempfile.mkdtemp(prefix="cfg-"))
        shutil.copy(work / "out" / f"{i}.toml", d / cfg.CONFIG_LOCAL)
        try:
            c = cfg.load_config(client_dir=d, env={})
        except cfg.ConfigError as e:
            if "read their PIN from" not in str(e):          # that one is the guard doing its job
                finding("the template writes a config the client refuses: "
                        + str(e).split(": ", 1)[-1].split(" (at ")[0][:70], want, e)
            continue
        finally:
            shutil.rmtree(d, ignore_errors=True)
        for name in set(case["sedo_roles"].values()):
            got = c.keys.get(name)
            if got is None:
                finding("a profile is lost or renamed on the way", name, list(c.keys))
                continue
            for field, value in want[name].items():
                if getattr(got, field) != value:
                    finding(f"{field} changes on the way through the template", value, getattr(got, field))
        shared = collections.Counter(p.effective_pin_env for p in c.distinct_profiles() if not p.pin_env and not p.pin)
        if any(n > 1 for n in shared.values()):
            finding("two profiles read their PIN from one variable and the client accepts it",
                    [p.name for p in c.distinct_profiles()])


if __name__ == "__main__":
    main("Ansible: vault PINs and config_local.toml.j2", fuzz_vault_pins, fuzz_config_template)
