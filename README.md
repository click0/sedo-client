# sedo-client

**Automation of the Ukrainian Armed Forces EDMS** (`sedo.mod.gov.ua`)
via the Almaz-1K USB token and IIT "Користувач ЦСК-1" (End User).

*Читати українською: [README_uk.md](README_uk.md).*

```
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.26
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

---

## Purpose

A nightly cron job driven from a Linux host that:

1. Logs into the SEDO portal of the Armed Forces of Ukraine using an Almaz-1K
   qualified electronic signature (KEP)
2. Downloads new documents from the inbox
3. Verifies signatures with [`ua-sign-verify`](https://github.com/click0)
4. Sends a Telegram report

Everything runs unattended — no operator prompts.

## Architecture

```
Linux Ansible controller
    │ WinRM (HTTPS 5986)
    ▼
Windows worker
    │
    ├── sedo_client.py (Python)
    │       │
    │       └─ opensc_signer.py  ──▶  pkcs11-tool.exe  (OpenSC 32-bit)
    │              or
    │           pkcs11_signer.py ──▶  PyKCS11
    │              or
    │           iit_client.py    ──▶  JSON-RPC to EUSignAgent
    │                                    │
    │                                    ▼
    │                         IIT "Користувач ЦСК" (GUI running)
    │
    └── PKCS11.EKeyAlmaz1C.dll + CSPBase.dll + CSPExtension.dll + *.cap
            │
            ▼ WinSCard (PC/SC)
        Almaz-1K USB
```

Three selectable backends:

| Backend | Pros | Dependency |
|---|---|---|
| **`opensc`** | Simplest, ships with OpenSC | 32-bit OpenSC only |
| `pkcs11`    | Faster, Python-native        | OpenSC + PyKCS11 |
| `iit_agent` | No OpenSC required           | IIT "Користувач ЦСК" GUI running |

## Quick start

### Windows worker

```powershell
# 1. Install Python and dependencies
winget install Python.Python.3.12
git clone <repo> C:\sedo-client
cd C:\sedo-client
pip install -r requirements.txt

# 2. Validate the whole stack
.\opensc-test-almaz.ps1
# Expected output:
#   - Found PKCS11.EKeyAlmaz1C.dll
#   - Bitness: 32-bit, PickedTool: 32-bit OpenSC ✓
#   - Reader: IIT E.Key Almaz-1C 0
#   - 12 mechanisms, including 0x80420031 (DSTU 4145 sign)

# 3. Signing test (careful — uses real token)
.\opensc-test-almaz.ps1 -Pin XXXX -TestSign

# 4. Real run
python sedo_client.py --backend opensc `
    --module "C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\PKCS11.EKeyAlmaz1C.dll" `
    --pin XXXX --fetch
```

### Linux controller

```bash
cd ansible
ansible-vault create inventory/vault.yml
# (format — see vault.yml.example)

ansible-playbook -i inventory/hosts.yml playbooks/sedo_daily.yml --ask-vault-pass

# Daily cron at 08:00
0 8 * * * cd /opt/sedo-client/ansible && \
    ansible-playbook -i inventory/hosts.yml playbooks/sedo_daily.yml \
        --vault-password-file /opt/sedo-client/.vault_pass \
        >> /var/log/sedo-client.log 2>&1
```

## Layout

```
sedo-client/
├── sedo_client.py              — business logic, auto backend picker, CLI
├── iit_client.py               — JSON-RPC client for EUSignAgent
├── opensc_signer.py            — OpenSC subprocess backend (recommended)
├── pkcs11_signer.py            — PyKCS11 direct backend
├── mechanism_ids.py            — PKCS#11 mechanism ID constants (DSTU 4145)
├── opensc-test-almaz.ps1       — PowerShell stack validator for Windows
├── requirements.txt
├── tests/
│   ├── conftest.py
│   └── test_iit_client.py      — 13 unit tests
├── scripts/
│   ├── fiddler_analyze.py      — parses a Fiddler SAZ capture
│   └── smoke_test.py           — quick environment check
├── ansible/
│   ├── inventory/
│   │   ├── hosts.yml
│   │   └── vault.yml.example
│   └── playbooks/
│       └── sedo_daily.yml
├── docs/                       — architecture, reverse-engineering report,
│                                 JSON-RPC protocol, mechanism table
├── .github/workflows/
│   ├── spellcheck.yml          — cspell on push / PR
│   └── release.yml             — triggered by v* tags
├── .cspell.json
├── README.md                   — this file (English)
├── README_uk.md                — Ukrainian version
├── SETUP-WINDOWS.md            — step-by-step Windows checklist
├── OPENSC-QUICKSTART.md        — hands-on OpenSC reference
├── FIDDLER-CAPTURE-GUIDE.md    — how to capture SEDO auth flow
├── CHANGELOG.md
└── LICENSE
```

## Security

⚠️ **The Almaz-1K destroys the private key after 15 failed PIN attempts.**
- Validate the PIN by hand before enabling automation
- Store the PIN only in Ansible Vault
- Use `no_log: true` on every task that handles the PIN
- The `opensc` backend passes the PIN on the `pkcs11-tool` command line,
  where it is visible to other local users via the process list; on
  multi-user Windows workers prefer `backend=iit_agent`

## Tests

```bash
pip install pytest requests
python -m pytest tests/ -v
# 13 passed
```

## CI

- **Spellcheck** (`.github/workflows/spellcheck.yml`) — `cspell` runs on every
  push and pull request against `main`. Cyrillic runs are ignored via a regex
  in `.cspell.json`; the whitelist covers project jargon (DSTU, PKCS, IIT,
  Kupyna, Kalyna, …).
- **Release** (`.github/workflows/release.yml`) — triggered by pushing a
  `v*` tag. Runs the test suite, extracts the matching section from
  `CHANGELOG.md`, packages `tar.gz` + `zip` archives, and publishes a
  GitHub Release.

To cut a release:

```bash
git tag v0.26
git push origin v0.26
```

## Related projects

- **ua-sign-verify** ([github.com/click0](https://github.com/click0)) —
  verifier for DSTU 4145 / Kupyna / GOST 34.311 KEP signatures, used on the
  Linux controller to verify documents after they are downloaded.

## Links

- IIT "Користувач ЦСК-1": https://iit.com.ua/download/productfiles/users
- OpenSC: https://github.com/OpenSC/OpenSC
- SEDO (Armed Forces of Ukraine): https://sedo.mod.gov.ua

---

## Documentation

Detailed documentation lives in [`docs/`](docs/):

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture overview and
  data flow
- [`docs/IIT-ANALYSIS.md`](docs/IIT-ANALYSIS.md) — full reverse-engineering
  report of 36+ IIT DLLs
- [`docs/MECHANISM-IDS.md`](docs/MECHANISM-IDS.md) — 12 PKCS#11 mechanism IDs
  of Almaz-1K
- [`docs/PROTOCOL-JSON-RPC.md`](docs/PROTOCOL-JSON-RPC.md) — IIT agent
  JSON-RPC protocol reference
- [`docs/REVERSE-METHODOLOGY.md`](docs/REVERSE-METHODOLOGY.md) — DLL analysis
  methodology
- [`docs/MINIMUM-FILES-LIST.md`](docs/MINIMUM-FILES-LIST.md) — deployment
  minimum

Setup guides:

- [`SETUP-WINDOWS.md`](SETUP-WINDOWS.md) — Windows worker walkthrough
- [`OPENSC-QUICKSTART.md`](OPENSC-QUICKSTART.md) — OpenSC commands for Almaz
- [`FIDDLER-CAPTURE-GUIDE.md`](FIDDLER-CAPTURE-GUIDE.md) — capturing the SEDO
  auth flow
- [`CHANGELOG.md`](CHANGELOG.md) — version history

---

## Prior art and related work

We surveyed GitHub before building sedo-client. **No direct equivalent exists
for `sedo.mod.gov.ua` + Almaz-1K + Ansible automation** — sedo-client fills
that gap.

### Ukrainian cryptography

- **[dstucrypt](https://github.com/dstucrypt)** (Ilya Muromec) — a full
  DSTU 4145 ecosystem:
  - [`dstu-engine`](https://github.com/dstucrypt/dstu-engine) — active OpenSSL
    engine for DSTU 4145 / 7564 / 28147; an alternative to the IIT DLLs on
    Linux
  - [`agent`](https://github.com/dstucrypt/agent) — Node.js signing agent for
    `Key-6.dat`
  - [`jkurwa`](https://github.com/dstucrypt/jkurwa) — JavaScript DSTU 4145
  - [`dstu-validator`](https://github.com/dstucrypt/dstu-validator) — HTTP
    API verifier

- **[GorulkoAV/EUSignDFS](https://github.com/GorulkoAV/EUSignDFS)** — C#
  wrapper around `EUSignCP.dll` (for Ukraine's State Fiscal Service);
  demonstrates the P/Invoke approach to IIT libraries.

### Infrastructure

- **[LudovicRousseau/CCID](https://github.com/LudovicRousseau/CCID)** —
  official CCID driver. Almaz-1K (`0x03EB:0x9324`) has been supported since
  1.4.15; Linux + `pcscd` talks to the token natively.

- **[OpenSC/OpenSC](https://github.com/OpenSC/OpenSC)** — cross-platform
  PC/SC middleware. `pkcs11-tool` is the primary validation tool in
  `opensc-test-almaz.ps1`.

- **[LudovicRousseau/PyKCS11](https://github.com/LudovicRousseau/PyKCS11)** —
  Python bindings for PKCS#11, used by the `pkcs11_signer.py` backend.

### Signature verification

- **[ua-sign-verify](https://github.com/click0)** (author's own project) —
  DSTU 4145 / Kupyna / GOST 34.311 KEP signature verifier. sedo-client calls
  it on the Linux controller to verify every fetched document.

### What does not exist elsewhere

Our project is the only publicly available tool that covers all of:

- SEDO Armed Forces (`sedo.mod.gov.ua`) login automation
- Ansible playbook ↔ Windows worker ↔ Almaz-1K integration
- Three-backend architecture (opensc / pkcs11 / iit_agent)
- The full cycle: login → fetch → verify → Telegram report
