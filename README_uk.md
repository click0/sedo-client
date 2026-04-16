# sedo-client

**Автоматизація СЕДО Збройних Сил України** (`sedo.mod.gov.ua`)  
через Алмаз-1К USB токен і ІІТ "Користувач ЦСК-1".

*Read this in [English](README.md).*

```
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.26
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

---

## Призначення

Щоденний cron з Linux:

1. Заходить у СЕДО ЗСУ через Алмаз-1К (КЕП підпис)
2. Завантажує нові документи
3. Верифікує підписи через `ua-sign-verify`
4. Шле Telegram-звіт

Все працює автоматично без втручання оператора.

## Архітектура

```
Linux Ansible controller
    │ WinRM (HTTPS 5986)
    ▼
Windows worker
    │
    ├── sedo_client.py (Python)
    │       │
    │       └─ opensc_signer.py  ──▶  pkcs11-tool.exe  (OpenSC 32-bit)
    │              або
    │           pkcs11_signer.py ──▶  PyKCS11
    │              або
    │           iit_client.py    ──▶  JSON-RPC до EUSignAgent
    │                                    │
    │                                    ▼
    │                         IIT "Користувач ЦСК" (GUI запущено)
    │
    └── PKCS11.EKeyAlmaz1C.dll + CSPBase.dll + CSPExtension.dll + *.cap
            │
            ▼ WinSCard (PC/SC)
        Алмаз-1К USB
```

Три backend на вибір:

| Backend | Перевага | Залежність |
|---|---|---|
| **`opensc`** | Простий, вбудований OpenSC tool | Тільки 32-bit OpenSC |
| `pkcs11` | Швидший, Python-native | OpenSC + PyKCS11 |
| `iit_agent` | Без OpenSC зовсім | "Користувач ЦСК" GUI запущено |

## Швидкий старт

### Windows worker

```powershell
# 1. Встановити Python і залежності
winget install Python.Python.3.12
git clone <repo> C:\sedo-client
cd C:\sedo-client
pip install -r requirements.txt

# 2. Валідація всього стеку
.\opensc-test-almaz.ps1
# Має вивести:
#   - Знайдено PKCS11.EKeyAlmaz1C.dll
#   - Бітність: 32-bit, PickedTool: 32-bit OpenSC ✓
#   - Reader: IIT E.Key Almaz-1C 0
#   - 12 mechanisms, включно з 0x80420031 (DSTU 4145 sign)

# 3. Тест підпису (обережно!)
.\opensc-test-almaz.ps1 -Pin XXXX -TestSign

# 4. Реальний запуск
python sedo_client.py --backend opensc `
    --module "C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\PKCS11.EKeyAlmaz1C.dll" `
    --pin XXXX --fetch
```

### Linux controller

```bash
cd ansible
ansible-vault create inventory/vault.yml
# (формат — див. vault.yml.example)

ansible-playbook -i inventory/hosts.yml playbooks/sedo_daily.yml --ask-vault-pass

# Cron щодня о 8:00
0 8 * * * cd /opt/sedo-client/ansible && \
    ansible-playbook -i inventory/hosts.yml playbooks/sedo_daily.yml \
        --vault-password-file /opt/sedo-client/.vault_pass \
        >> /var/log/sedo-client.log 2>&1
```

## Структура

```
sedo-client/
├── sedo_client.py              — бізнес-логіка, авто-вибір backend, CLI
├── iit_client.py               — JSON-RPC клієнт до EUSignAgent
├── opensc_signer.py            — OpenSC subprocess backend (рекомендовано)
├── pkcs11_signer.py            — PyKCS11 direct backend
├── mechanism_ids.py            — константи mechanism IDs (DSTU 4145)
├── opensc-test-almaz.ps1       — PowerShell валідація стеку на Windows
├── requirements.txt
├── tests/
│   ├── conftest.py
│   └── test_iit_client.py      — 13 юніт-тестів
├── scripts/
│   ├── fiddler_analyze.py      — розбирає Fiddler SAZ capture
│   └── smoke_test.py           — швидка перевірка середовища
├── ansible/
│   ├── inventory/
│   │   ├── hosts.yml
│   │   └── vault.yml.example
│   └── playbooks/
│       └── sedo_daily.yml
├── docs/                       — архітектура, звіт реверсу, протокол
├── .github/workflows/
│   ├── spellcheck.yml          — cspell на push/PR
│   └── release.yml             — тригер на тег v*
├── .cspell.json
├── README.md                   — English
├── README_uk.md                — ця сторінка
├── SETUP-WINDOWS.md            — покроковий checklist Windows
├── OPENSC-QUICKSTART.md        — робота з OpenSC напряму
├── FIDDLER-CAPTURE-GUIDE.md    — як зафіксувати auth flow СЕДО
├── CHANGELOG.md
└── LICENSE
```

## Безпека

⚠️ **Алмаз-1К знищує приватний ключ після 15 невдалих спроб PIN.**
- Валідуйте PIN вручну перед автоматизацією
- Зберігайте PIN тільки в Ansible Vault
- `no_log: true` у всіх task-ах де фігурує PIN

## Тести

```bash
pip install pytest requests
python -m pytest tests/ -v
# 13 passed
```

## Залежні проекти

- **ua-sign-verify** ([github.com/click0](https://github.com/click0)) — верифікатор КЕП підписів ДСТУ 4145 / ГОСТ 34.311

## Посилання

- IIT "Користувач ЦСК-1": https://iit.com.ua/download/productfiles/users
- OpenSC: https://github.com/OpenSC/OpenSC
- СЕДО ЗСУ: https://sedo.mod.gov.ua

---

## Документація

Детальна документація у [`docs/`](docs/):

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — огляд архітектури, data flow
- [`docs/IIT-ANALYSIS.md`](docs/IIT-ANALYSIS.md) — повний звіт реверс-інжинірингу 36+ DLL ІІТ
- [`docs/MECHANISM-IDS.md`](docs/MECHANISM-IDS.md) — 12 PKCS#11 mechanism IDs Алмаз-1К
- [`docs/PROTOCOL-JSON-RPC.md`](docs/PROTOCOL-JSON-RPC.md) — JSON-RPC протокол IIT агента
- [`docs/REVERSE-METHODOLOGY.md`](docs/REVERSE-METHODOLOGY.md) — методологія аналізу DLL
- [`docs/MINIMUM-FILES-LIST.md`](docs/MINIMUM-FILES-LIST.md) — deployment минимум

Setup гайди:

- [`SETUP-WINDOWS.md`](SETUP-WINDOWS.md) — покрокове налаштування Windows worker
- [`OPENSC-QUICKSTART.md`](OPENSC-QUICKSTART.md) — OpenSC команди для Алмаз
- [`FIDDLER-CAPTURE-GUIDE.md`](FIDDLER-CAPTURE-GUIDE.md) — як зафіксувати auth flow СЕДО
- [`CHANGELOG.md`](CHANGELOG.md) — історія версій

---

## Prior art та пов'язані проекти

Ми вивчали існуючі рішення на GitHub перед створенням sedo-client. **Прямого
аналога для автоматизації `sedo.mod.gov.ua` + Алмаз-1К + Ansible не існує** —
sedo-client заповнює цю нішу.

Однак ми спираємось на кілька чудових проектів:

### Українська криптографія

- **[dstucrypt](https://github.com/dstucrypt)** (Ilya Muromec) — повна екосистема DSTU 4145:
  - [`dstu-engine`](https://github.com/dstucrypt/dstu-engine) — активний OpenSSL engine для DSTU 4145/7564/28147. Альтернатива ІІТ DLL на Linux
  - [`agent`](https://github.com/dstucrypt/agent) — Node.js agent для підпису через Key-6.dat
  - [`jkurwa`](https://github.com/dstucrypt/jkurwa) — JavaScript DSTU 4145
  - [`dstu-validator`](https://github.com/dstucrypt/dstu-validator) — HTTP API верифікатор

- **[GorulkoAV/EUSignDFS](https://github.com/GorulkoAV/EUSignDFS)** — C# wrapper для `EUSignCP.dll`
  (для Державної фіскальної служби). Показує підхід до P/Invoke IIT бібліотеки.

### Інфраструктура

- **[LudovicRousseau/CCID](https://github.com/LudovicRousseau/CCID)** — офіційний CCID driver.
  Алмаз-1К (`0x03EB:0x9324`) підтримується з версії 1.4.15. Linux + `pcscd` читає токен нативно.

- **[OpenSC/OpenSC](https://github.com/OpenSC/OpenSC)** — крос-платформовий PC/SC middleware.
  `pkcs11-tool` використовується як головний інструмент валідації у `opensc-test-almaz.ps1`.

- **[LudovicRousseau/PyKCS11](https://github.com/LudovicRousseau/PyKCS11)** — Python binding
  для PKCS#11, використовується у `pkcs11_signer.py` backend.

### Верифікація підписів

- **[ua-sign-verify](https://github.com/click0)** (цей проект автора) — верифікатор КЕП підписів
  ДСТУ 4145 / Kupyna / ГОСТ 34.311. Використовується у sedo-client для post-fetch верифікації
  завантажених документів на Linux controller.

### Чого НЕ існує

Наш проект — єдиний публічний, що покриває:
- Автоматизацію авторизації СЕДО ЗСУ (`sedo.mod.gov.ua`)
- Інтеграцію Ansible playbook ↔ Windows worker ↔ Алмаз-1К
- Трьохбекендну архітектуру (opensc / pkcs11 / iit_agent)
- Повний cycle: login → fetch → verify → Telegram report
