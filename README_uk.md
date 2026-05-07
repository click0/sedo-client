# sedo-client

**Автоматизація СЕДО Збройних Сил України** (`sedo.mod.gov.ua`)
через USB-токен Алмаз-1К та ІІТ "Користувач ЦСК-1".

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

Щоденний cron з Linux-хоста:

1. Заходить у портал СЕДО ЗСУ через Алмаз-1К та кваліфікований електронний
   підпис (КЕП)
2. Завантажує нові документи зі вхідних
3. Верифікує підписи за допомогою [`ua-sign-verify`](https://github.com/click0)
4. Надсилає Telegram-звіт

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
        Almaz-1K USB
```

Три backend-и на вибір:

| Backend | Переваги | Залежність |
|---|---|---|
| **`opensc`** | Найпростіший, входить до OpenSC | Тільки 32-bit OpenSC |
| `pkcs11`    | Швидший, Python-native           | OpenSC + PyKCS11 |
| `iit_agent` | Не потрібен OpenSC               | IIT "Користувач ЦСК" GUI запущено |

## Швидкий старт

### Windows worker

```powershell
# 1. Встановити Python та залежності
winget install Python.Python.3.12
git clone <repo> C:\sedo-client
cd C:\sedo-client
pip install -r requirements.txt

# 2. Валідація всього стеку
.\opensc-test-almaz.ps1
# Очікуваний вивід:
#   - Знайдено PKCS11.EKeyAlmaz1C.dll
#   - Бітність: 32-bit, PickedTool: 32-bit OpenSC ✓
#   - Reader: IIT E.Key Almaz-1C 0
#   - 12 mechanisms, включно з 0x80420031 (DSTU 4145 sign)

# 3. Тест підпису (обережно — використовує реальний токен)
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

# Cron щодня о 08:00
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
├── mechanism_ids.py            — константи PKCS#11 mechanism IDs (DSTU 4145)
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
├── docs/                       — архітектура, звіт реверсу,
│                                 JSON-RPC протокол, таблиця механізмів
├── .github/workflows/
│   ├── spellcheck.yml          — cspell на push / PR
│   └── release.yml             — тригер на тег v*
├── .cspell.json
├── README.md                   — English
├── README_uk.md                — цей файл (українська)
├── SETUP-WINDOWS.md            — покроковий чеклист Windows
├── OPENSC-QUICKSTART.md        — довідник OpenSC команд
├── FIDDLER-CAPTURE-GUIDE.md    — як зафіксувати auth flow СЕДО
├── CHANGELOG.md
└── LICENSE
```

## Безпека

⚠️ **Алмаз-1К знищує приватний ключ після 15 невдалих спроб PIN.**
- Валідуйте PIN вручну перед автоматизацією
- Зберігайте PIN тільки в Ansible Vault
- Використовуйте `no_log: true` у кожному task-і, що працює з PIN
- Backend `opensc` передає PIN у командному рядку `pkcs11-tool`, де він
  видимий іншим локальним користувачам через список процесів; на
  багатокористувацьких Windows-воркерах використовуйте `backend=iit_agent`

## Тести

```bash
pip install pytest requests
python -m pytest tests/ -v
# 13 passed
```

## CI

- **Spellcheck** (`.github/workflows/spellcheck.yml`) — `cspell` запускається
  на кожному push та pull request в `main`. Кирилиця ігнорується через regex
  у `.cspell.json`; whitelist покриває проектний жаргон (DSTU, PKCS, IIT,
  Kupyna, Kalyna, …).
- **Release** (`.github/workflows/release.yml`) — тригериться push-ем тегу
  `v*`. Запускає тести, витягує відповідну секцію з `CHANGELOG.md`, пакує
  архіви `tar.gz` + `zip` та публікує GitHub Release.

Щоб зробити реліз:

```bash
git tag v0.26
git push origin v0.26
```

## Пов'язані проекти

- **ua-sign-verify** ([github.com/click0](https://github.com/click0)) —
  верифікатор підписів КЕП ДСТУ 4145 / Kupyna / ГОСТ 34.311, використовується
  на Linux controller для перевірки завантажених документів.

## Посилання

- IIT "Користувач ЦСК-1": https://iit.com.ua/download/productfiles/users
- OpenSC: https://github.com/OpenSC/OpenSC
- СЕДО ЗСУ: https://sedo.mod.gov.ua

---

## Документація

Детальна документація у [`docs/`](docs/):

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — огляд архітектури та
  data flow
- [`docs/IIT-ANALYSIS.md`](docs/IIT-ANALYSIS.md) — повний звіт
  реверс-інжинірингу 36+ DLL ІІТ
- [`docs/MECHANISM-IDS.md`](docs/MECHANISM-IDS.md) — 12 PKCS#11 mechanism IDs
  Алмаз-1К
- [`docs/PROTOCOL-JSON-RPC.md`](docs/PROTOCOL-JSON-RPC.md) — довідник
  JSON-RPC протоколу агента ІІТ
- [`docs/REVERSE-METHODOLOGY.md`](docs/REVERSE-METHODOLOGY.md) — методологія
  аналізу DLL
- [`docs/MINIMUM-FILES-LIST.md`](docs/MINIMUM-FILES-LIST.md) — мінімум для
  деплою

Гайди з налаштування:

- [`SETUP-WINDOWS.md`](SETUP-WINDOWS.md) — покрокове налаштування Windows worker
- [`OPENSC-QUICKSTART.md`](OPENSC-QUICKSTART.md) — команди OpenSC для Алмаз
- [`FIDDLER-CAPTURE-GUIDE.md`](FIDDLER-CAPTURE-GUIDE.md) — як зафіксувати
  auth flow СЕДО
- [`CHANGELOG.md`](CHANGELOG.md) — історія версій

---

## Prior art та пов'язані проекти

Ми дослідили GitHub перед створенням sedo-client. **Прямого аналога для
`sedo.mod.gov.ua` + Алмаз-1К + Ansible автоматизації не існує** — sedo-client
заповнює цю нішу.

### Українська криптографія

- **[dstucrypt](https://github.com/dstucrypt)** (Ilya Muromec) — повна
  екосистема DSTU 4145:
  - [`dstu-engine`](https://github.com/dstucrypt/dstu-engine) — активний
    OpenSSL engine для DSTU 4145 / 7564 / 28147; альтернатива DLL ІІТ на Linux
  - [`agent`](https://github.com/dstucrypt/agent) — Node.js agent для
    підпису через `Key-6.dat`
  - [`jkurwa`](https://github.com/dstucrypt/jkurwa) — JavaScript DSTU 4145
  - [`dstu-validator`](https://github.com/dstucrypt/dstu-validator) — HTTP
    API верифікатор

- **[GorulkoAV/EUSignDFS](https://github.com/GorulkoAV/EUSignDFS)** — C#
  обгортка навколо `EUSignCP.dll` (для Державної фіскальної служби); демонструє
  підхід P/Invoke до бібліотек ІІТ.

### Інфраструктура

- **[LudovicRousseau/CCID](https://github.com/LudovicRousseau/CCID)** —
  офіційний CCID driver. Алмаз-1К (`0x03EB:0x9324`) підтримується з версії
  1.4.15; Linux + `pcscd` спілкується з токеном нативно.

- **[OpenSC/OpenSC](https://github.com/OpenSC/OpenSC)** — крос-платформний
  PC/SC middleware. `pkcs11-tool` — основний інструмент валідації у
  `opensc-test-almaz.ps1`.

- **[LudovicRousseau/PyKCS11](https://github.com/LudovicRousseau/PyKCS11)** —
  Python-binding для PKCS#11, використовується у backend `pkcs11_signer.py`.

### Верифікація підписів

- **[ua-sign-verify](https://github.com/click0)** (проект автора) —
  верифікатор підписів КЕП ДСТУ 4145 / Kupyna / ГОСТ 34.311. sedo-client
  викликає його на Linux controller для перевірки кожного завантаженого
  документа.

### Чого НЕ існує

Наш проект — єдиний публічний інструмент, що покриває:

- Автоматизацію логіну в СЕДО ЗСУ (`sedo.mod.gov.ua`)
- Інтеграцію Ansible playbook ↔ Windows worker ↔ Алмаз-1К
- Трибекендну архітектуру (opensc / pkcs11 / iit_agent)
- Повний цикл: логін → завантаження → верифікація → Telegram-звіт
