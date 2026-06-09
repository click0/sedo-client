# CHANGELOG

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
License:  BSD 3-Clause "New" or "Revised" License
```

## Unreleased

### Виправлено (критичне)

- **`pip install .` був зламаний**: `pyproject.toml` мав неіснуючий
  `build-backend = "setuptools.backends._legacy:_Backend"`. Виправлено на
  `setuptools.build_meta`. Перевірено: wheel збирається, console-script
  `sedo-client` присутній. Жоден CI-крок цього не ловив (release пакує
  git archive, build-воркфлоу — PyInstaller).
- **Avest у backend `opensc` підписувався неправильним механізмом**:
  `OpenSCSigner` хардкодив IIT `0x80420031`, тож `--backend opensc --module
  Av337CryptokiD.dll` (ST-338) використовував не той mechanism. Тепер
  `_pick_backend` визначає mechanism за модулем через
  `detect_dstu4145_mechanism()` (IIT → 0x80420031, Avest → 0x00000352) і
  передає його в `OpenSCSigner`. Закриває і режим `auto`, де opensc
  пробується першим. +2 тести.

### Виправлено (гігієна)

- `SEDOClient.__exit__` тепер закриває HTTP-сесію навіть якщо `logout()`
  кинув виняток (раніше — витік сокета); додано `return False`
- `download_document()` створює `output_dir` сам (раніше mkdir був лише в
  `main()` — падало при використанні як бібліотеки)
- `authorize()` сигнатура `-> None` (раніше `-> bool`, але метод завжди
  повертав `True` або кидав — анотація брехала)

### Тести

- **+15 тестів HTTP-шару** (`test_sedo_client.py`, всього 88): auth-flow
  (oidc / direct_kep / cms_post), `authorize` (успіх і повний провал),
  `fetch_inbox` (документи, since-параметр, HTTP-помилка),
  `download_document` (запис zip + створення каталогу), вибір механізму
  opensc для IIT/Avest, закриття сесії при винятку logout

### Виправлено (Windows)

- **Краш на українській Windows-консолі**: `print("✓ ...")` падав із
  `UnicodeEncodeError` (cp1251/cp866 не має emoji ✓ 📄 ❌) одразу після
  успішної авторизації. Додано `force_utf8_io()` — переключає stdout/stderr
  на UTF-8 на старті всіх 4 CLI (sedo_client, iit_client, opensc_signer,
  pkcs11_signer). +2 регресійні тести.

### CI / збірка

- **Standalone бінарники** через PyInstaller у 3 нових воркфлоу:
  - `.github/workflows/build-windows.yml` — `.exe` (windows-latest)
  - `.github/workflows/build-unix.yml` — Linux ELF (ubuntu) +
    FreeBSD ELF (vmactions/freebsd-vm)
  - `scripts/build_binary.py` — крос-платформний build helper з коректним
    bundling lazy-import backends і опціонального PyKCS11
- Бінарники тригеряться на тег `v*` і прикріплюються до GitHub Release;
  також доступні через workflow_dispatch як артефакти

### Додано

- **Підтримка токенів Avest CC-337 / SecureToken-338** (`Av337CryptokiD.dll`)
  та Avest AvestKey / EfitKey (`avcryptokinxt.dll`) у backend `pkcs11`
- `mechanism_ids.detect_token_vendor()` — визначення вендора за ім'ям модуля
  ("iit" / "iit_virtual" / "avest" / "unknown")
- `mechanism_ids.pick_sign_mechanism()` — вибір DSTU 4145 sign-механізму зі
  списку доступних, з реєстром `DSTU4145_SIGN_MECHANISMS`
- `find_sign_mechanism()` тепер пріоритезує відомі DSTU 4145 ID (IIT
  0x80420031/32 і Avest стандартний 0x00000352) перед загальною евристикою —
  виправляє вибір механізму для Avest ST-338 (стандартний ID < 0x80000000)
- Avest-шляхи додано до `PKCS11Signer.DEFAULT_MODULE_PATHS`
- 15 нових юніт-тестів (`tests/test_avest.py`)

## v0.27 — 2026-06-08

### Тести та якість

- 56 юніт-тестів (було 13): `test_sedo_client.py` (17), `test_opensc_signer.py` (14),
  `test_virtual_signer.py` (12), `test_iit_client.py` (13)
- `pyproject.toml` — pip-installable: `pip install .` або `pip install .[all]`
- `__all__` у всіх 6 Python-модулях — визначена публічна API-поверхня

### Виправлено (runtime bugs)

- `iit_client.py`: `sign_data`/`sign_hash` — захист `base64.b64decode` від
  малформованих відповідей агента; перевірка None-результату
- `sedo_client.py`: `--backend virtual` без Key-6.dat тепер raises
  `FileNotFoundError` (було: мовчки None → cryptic crash при login)
- `sedo_client.py`: challenge type guard у `_flow_direct_kep` — тепер
  приймає лише `str`/`bytes`, не list/dict
- `sedo_client.py`: `doc.get("id")` замість `doc["id"]` у fetch loop
  (було: KeyError якщо API повертає документ без id)
- `sedo_client.py`: `authorize()` exception catch звужено до конкретних
  типів (було: `except Exception` ковтало KeyboardInterrupt)
- `pkcs11_signer.py`: mechanism discovery failure у `login()` тепер
  propagates (було: warning → misleading error при `sign()`)

### Безпека

- `opensc_signer.py`: PIN замаскований у debug-логах (`--pin ***`)
- Consistent `return False` у всіх `__exit__` методах

### Hardening

- Mutex `Global\EKAlmaz1COpenMutex` додано до pre-flight check
- AppData/Roaming path додано до `VirtualSigner.DEFAULT_VIRTUAL_PATHS`
- `requirements.txt`: знято `platform_system == "Windows"` з PyKCS11
  (потрібен на Linux для virtual backend через Wine)
- `.gitignore` += `.mypy_cache/`
- `smoke_test.py`: subprocess timeout=10
- `pkcs11_signer.py`/`virtual_signer.py`: logout — log перед pass
- `detect_dstu4145_mechanism`: Virtual module тепер потрапляє у перший
  branch (HW і Virtual share the same mechanism IDs)
- Мертвий код видалено: `ElementTree` import, `DEFAULT_HTTP/HTTPS_PORT`,
  `MECH_NAME_HINTS`; CLI-методи анотовані
- Ansible: `ansible_date_time.date` замість shell `date` (timezone safety)
- `fiddler_analyze.py`: SAZ session number parsing за реальними файлами
- `release.yml`: SHA256 checksums у GitHub Release
- `opensc_signer._run()`: stderr логується на debug level
- `docs/MINIMUM-FILES-LIST.md`: секція "Bitness: do not mix 32/64"
- `README_uk.md`: повний переклад англійського README

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
