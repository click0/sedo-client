# CHANGELOG

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
License:  BSD 3-Clause "New" or "Revised" License
```

## v0.26 — 2026-04-16

### Додано

- **Virtual backend** (`virtual_signer.py`): PKCS11.Virtual.EKeyAlmaz1C.dll +
  Key-6.dat, працює без USB-токена (`--backend virtual --key-file Key-6.dat`)
- **Linux/Wine deployment**: `docs/LINUX-WINE-DEPLOYMENT.md` — покроковий
  cookbook для 32-bit Wine prefix, реєстрові ключі, виклик sedo-client
- **Linux Ansible playbook** (`ansible/playbooks/sedo_daily_linux.yml`):
  SEDO-перевірка без Windows worker і без WinRM
- **Inventory group** `sedo_workers_linux` у `hosts.yml`
- **Vault-змінна** `virtual_pins` у `vault.yml.example`
- **`mechanism_ids.MECHANISM_SUPPORT`** — матриця HW/Virtual сумісності для
  12 vendor mechanisms; функція `is_supported(mech_id, token_type)`
- **7 нових юніт-тестів** у `tests/test_virtual_signer.py` (discovery +
  mechanism matrix + CLI choices), всього 20 тестів

### Документація (на основі ADDENDUM v1-v6)

- `docs/IIT-ANALYSIS.md`: CSPExtension переосмислено як RNG self-test (BSI
  AIS 31), а не "ECDH + GOST wrap"; ім'я `sCSPIBase` → `CSPIBase`;
  статус `PKCS11.EKeyAlmaz1C.dll` оновлено на "отримано" (v1.0.1.7,
  32+64-bit); розміри `KM.EKeyAlmaz1C.dll` скориговано; mutex-и
  (`Global\EKAlmaz1CMutex`, `Global\EKAlmaz1CMemory`) задокументовано;
  додано KM-архітектуру (KM.dll + KM_FileSystem + KM_PKCS11 + KM_EKeyAlmaz1C)
- `docs/MINIMUM-FILES-LIST.md`: повний перепис — Scenario A (HW) vs
  Scenario B (Virtual); додано `PKIFormats.dll`, `CSPIBase.dll`,
  `EUSignCP.dll`, `KM.dll`, `KM_FileSystem.dll`; попередження про
  version drift між v5 (2025) і v6 (2017-2023) батчами DLL
- `docs/README.md`: посилання на всі 6 ADDENDUM-файлів
- `SETUP-WINDOWS.md`: FAQ-секція "Crystal-1 vs Almaz-1K" — Crystal-1
  не підтримується sedo-client (інший USB-driver, `VID:PID 03EB:9301`)

### Виправлено

- `sedo_client.py`: прибрано мертву гілку `if sedo.authorize(...)` (метод лише raises)
- `sedo_client.py`: виправлено ненадійну заміну URL у `_flow_direct_kep`
  (`url.rsplit("/", 1)` замість подвійного `replace`)
- `sedo_client.py`: `_flow_cms_post` тепер raises `NotImplementedError`
  замість тихого повернення `False`
- `sedo_client.py`: `IITAgentAdapter.login` raises при невідомому envelope
  сертифіката замість тихого `None`
- `iit_client.py`: `origin` default → `https://sedo.mod.gov.ua`
  (був старий `sedo.gov.ua`)
- `iit_client.py`: `r.json()` обгорнуто у `try/except` для не-JSON відповідей
- `iit_client.py`: виправлено partial-return при `OSError` у читанні реєстру
- `iit_client.py`: suppress `urllib3.InsecureRequestWarning`
  для self-signed HTTPS-агента
- `opensc_signer.py`: замінено bare `except: pass` на `except OSError`
- `opensc_signer.py`: `tempfile.mkstemp` + `os.close` щоб `pkcs11-tool`
  міг відкрити вихідний файл на Windows
- `pkcs11_signer.py`: прибрано малоймовірний шлях `SysWOW64`, додано
  підтверджений інсталером IIT шлях `EKeys\Almaz1C`
- `ansible/inventory/hosts.yml`: `sedo_url` → `sedo.mod.gov.ua`
- `ansible/playbooks/sedo_daily.yml`: використовує `{{ sedo_url }}`
  з інвентарю, прибрано фантомний `rc=2` у `failed_when`
- `docs/IIT-ANALYSIS.md`: усі приклади оновлено на `sedo.mod.gov.ua`

### Змінено

- `tests/conftest.py`: новий файл з централізованим `sys.path`
- Прибрано `sys.path.insert(0, "..")` хак зі `test_iit_client.py`

### Безпека

- Задокументовано leak PIN через командний рядок `pkcs11-tool`
  (видимий іншим локальним користувачам); рекомендація `backend=iit_agent`
  для багатокористувацьких worker-ів

## v0.25 — 2026-04-16

### Проривні

- Ідентифіковано точний DSTU 4145 mechanism ID через `--list-mechanisms`
  на живому Алмаз-1К: **`0x80420031`** (sign), не `0x80420014` як припускалось раніше
- `0x80420014` з розміром 32 байти — це симетричний MAC, не DSTU 4145
- Справжній DSTU 4145 — розмір ключа 163-509 біт (EC F_2M), mechanism `0x80420031/32`

### Додано

- `opensc_signer.py` — backend через subprocess до OpenSC pkcs11-tool
- `opensc-test-almaz.ps1` — інтерактивна валідація всього стеку:
  - Автопошук PKCS11 DLL у `EKeys\Almaz1C` та інших локаціях
  - Перевірка бітності DLL і pkcs11-tool (32-bit vs 64-bit)
  - Автозбір `.cap` файлів і додавання до PATH
  - `-TestSign` — тест підпису з перебором mechanism IDs
- `SETUP-WINDOWS.md` — чеклист налаштування worker
- `OPENSC-QUICKSTART.md` — довідник OpenSC команд
- `FIDDLER-CAPTURE-GUIDE.md` — як зафіксувати auth flow СЕДО

### Виправлено

- Правильний шлях у реєстрі IIT: `...\Sign Agent\Common` (було без `\Common`)
- Порти агента 8081/8083 (було 9100 як здогад)
- Реальний шлях PKCS11 DLL: `EKeys\Almaz1C` (було загальний пошук)
- URL СЕДО: `sedo.mod.gov.ua` (було `sedo.gov.ua`)
- `mechanism_ids.py`: правильна інтерпретація всіх 12 vendor mechanisms
- Видалено дубль `WINDOWS-SETUP.md` (залишився `SETUP-WINDOWS.md`)


### Досліджено

- Проведено пошук аналогів на GitHub (`sedo-client`, `IIT EUSignCP`, `DSTU4145`)
- Не знайдено прямого аналога для `sedo.mod.gov.ua` + Алмаз-1К + Ansible
- Знайдено релевантні проекти:
  - `dstucrypt/*` ecosystem (Ilya Muromec) — Linux/OpenSSL DSTU stack
  - `GorulkoAV/EUSignDFS` — C# wrapper `EUSignCP.dll`
  - CCID Алмаз-1К (`0x03EB:0x9324`) з v1.4.15 офіційного `libccid`
- Додано розділ `Prior art` у `README.md` з посиланнями
## v0.10 — 2026-04 (internal)

- Первинний реверс IIT DLL (36+ бінарок)
- Python-клієнт з двома backend (iit_agent, pkcs11)
- Ansible playbook для WinRM
- 13 юніт-тестів
