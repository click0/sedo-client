# CLAUDE.md — інструкції для сесій Claude Code у цьому репозиторії

## Перше, що зробити в новому клоні

```bash
git pull origin main
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install ".[test,analysis]"                   # + ".[pkcs11]", якщо потрібен справжній PyKCS11
```

PyKCS11 для тестів не потрібен: `tests/conftest.py` підставляє фейковий
модуль (`fake_pykcs11`). Справжній стек (SoftHSM2 + OpenSC + PyKCS11) ганяє
лише `tests/test_integration_softhsm.py`; без `softhsm2` він пропускається.

## Мова спілкування

Відповідати користувачу **українською**. Код, коміти, PR — англійською.
CHANGELOG ведеться українською. README двомовний: `README.md` (EN) і
`README_uk.md` (UK) — зміни вносити в обидва. Коментарі в коді бувають і
українською, і англійською, як у наявному коді.

## Перевірки перед комітом

Те саме, що ганяє CI (`.github/workflows/tests.yml`, `spellcheck.yml`):

```bash
python -m pytest tests/ -q                       # 3.11–3.13 у CI, плюс Windows
python scripts/check_version.py                  # заголовки Version: = pyproject
npx cspell@9 --config .cspell.json "**/*.md" "**/*.py" "**/*.yml" "**/*.yaml" "**/*.sh"
python -m build --wheel && pip install --force-reinstall --no-deps dist/*.whl && sedo-client --help
```

Нове слово, яке cspell не знає (прізвище, назва DLL, транслітерація), —
у `.cspell.json`, не в `cspell:disable`. Файли на Windows пишуться з явним
`encoding=` (`write_text(..., encoding="utf-8")`): Windows-джоба вже ловила
cp1252.

Бінарники (PyInstaller, `scripts/build_binary.py`) збираються лише в
`release.yml`. Перевірити їх до тега — запуск **Actions → Release → Run
workflow** з гілки: це dry-run, що збирає все (Linux, FreeBSD, Windows,
архіви, `sha256sums`) і нічого не публікує.

## Робочий процес

1. Гілка → PR у `main` → зелений CI → **merge-коміт** (не squash), як
   `Merge pull request #NN`. Префікси комітів: `feat:`, `fix(<область>):`,
   `chore:`, `ci(deps):`, `docs:`.
2. Dependabot раз на тиждень відкриває один згрупований PR для GitHub
   Actions (і окремо для pip); actions у workflow закріплені за SHA з
   коментарем версії.
3. Реліз: версія в `pyproject.toml` і в кожному заголовку `Version:`
   (модулі, документи, `opensc-test-almaz.ps1` — `check_version.py` їх
   звіряє), секція `## vX.Y — дата` у `CHANGELOG.md` (між релізами —
   `## vX.Y — unreleased`). Тег `vX.Y` ставить власник; `release.yml`
   спершу перевіряє, що тег = pyproject = CHANGELOG, тоді збирає й публікує
   один реліз із нотатками з CHANGELOG.

## Архітектура (коротко)

Код — пакет `sedo/` (`pyproject`: `packages = ["sedo"]`, консольна команда
`sedo-client` = `sedo.client:main`, також `python -m sedo`):

- `sedo/client.py` — `SEDOClient`, CLI, автовибір backend
  (`_pick_backend`), flow авторизації і завантаження документів.
- `sedo/config.py` — `config.toml` (у git, спільний) + `config_local.toml`
  (приватний), профілі ключів і ролі `auth`/`sign`. `default_config_dir()`:
  поруч із `.exe` у збірці PyInstaller; у checkout — корінь репозиторію (на
  рівень вище за пакет, впізнається за `pyproject.toml` / `config.toml`);
  у встановленому wheel — `%APPDATA%\sedo-client` або
  `~/.config/sedo-client` (`user_config_dir()`).
- `sedo/check.py` — `--check`: звіт про готовність без витрати спроби PIN.
- Підписувачі (backend-и):
  - `sedo/opensc_signer.py` — `pkcs11-tool` з OpenSC як subprocess
    (рекомендований шлях на Windows);
  - `sedo/pkcs11_signer.py` — PyKCS11 напряму з модулем ІІТ (Алмаз-1К,
    Avest);
  - `sedo/virtual_signer.py` — віртуальний токен (`Key-6.dat`) через
    PyKCS11, без USB;
  - `sedo/iit_client.py` — агент ІІТ «Користувач ЦСК-1» (JSON-RPC на
    localhost).
- `sedo/mechanism_ids.py` — ID механізмів PKCS#11, вибір DSTU 4145.
- `sedo/_console.py` — спільне для всіх CLI: UTF-8 консоль, PIN
  (`--pin` → `$SEDO_PIN` → запит), `$SEDO_MODULE`, `$SEDO_MODULE_DIRS`.
- `sedo/telegram_report.py` — Telegram-звіт наприкінці обох плейбуків
  (`python3 -m sedo.telegram_report` на контролері). Лише stdlib: на
  контролері пакетів клієнта може не бути.

Плейбуки: усі кроки воркера — в одному `block` з `rescue`, що записує
`sedo_worker_error`. Без цього провал усіх воркерів зупиняв би Ansible до
play верифікації, і звіт не надсилався б саме тоді, коли він потрібен.
Прогін завершується з помилкою останнім task-ом play верифікації. Не
додавай `ansible.builtin.fail` у `rescue`.

Кореневі `sedo_client.py`, `iit_client.py`, `opensc_signer.py`,
`pkcs11_signer.py` та інші старі імена — **шими**: як скрипт запускають ту
саму програму (так їх викликають документація, плейбуки Ansible і Wine),
при імпорті дають `DeprecationWarning` і підміняють себе модулем `sedo.*`.
Новий код і тести імпортують лише `sedo.<модуль>`; `monkeypatch`/`patch` —
по імені `sedo.<модуль>.<атрибут>`. `scripts/` пакет не імпортує (окрім
`smoke_test.py`), `iit_inventory.py` — лише stdlib.

## Інваріанти токена й ключів — не ламати

- **PIN ніколи не потрапляє в лог, виняток чи вивід.** `pkcs11-tool`
  логується з `--pin ***`, `TimeoutExpired` перевидається з замаскованою
  командою (сирий argv лишився б у ланцюжку винятків), RPC-методи агента з
  PIN — у `_REDACTED_METHODS`, `--show-config` друкує `redacted()`.
  Тести: `tests/test_pin_safety.py`, `tests/test_security.py`.
- **Секрет у плейбуку — не через `environment:` на Linux-хостах.** Ansible
  дописує його перед командою (`sh -c 'VAR=… python3 …'`), тож значення
  видно в лозі `-vvv` попри `no_log` і в `ps`. Токен Telegram тому йде JSON-ом
  у `stdin` під `no_log`. На Windows (WinRM) `environment:` іде в payload,
  не в командний рядок. Відоме порушення, ще не виправлене: `SEDO_PIN` у
  `environment:` запуску клієнта в `sedo_daily_linux.yml`.
- **PIN — через середовище або запит, не через argv клієнта.** `--pin`
  лишається, але позначений як найменш безпечний; плейбуки передають
  `SEDO_PIN`, профілі — `pin_env`/`pin_file`, PIN відкритим текстом у
  `config_local.toml` дає попередження. Відомий виняток: backend OpenSC
  передає PIN дочірньому `pkcs11-tool` як `--pin <PIN>`, тож на час його
  роботи PIN видно в списку процесів.
- **Порожній PIN відхиляється** до першого `C_Login` (`_console.read_pin`):
  на Алмаз-1К кожен невдалий вхід витрачає одну з 15 спроб, після яких ключ
  знищується. Тому й `--check` нічого не підписує і PIN не пробує.
- **Приватний ключ не покидає токен.** Клієнт лише просить підпис
  (`C_Sign` через модуль, `pkcs11-tool --sign`, `Sign` агента); з токена
  читається тільки `CKA_VALUE` сертифіката.
- **TLS:** запити до СЕДО — з перевіркою за системним сховищем (типовий
  `verify` у `requests`). Перевірка вимикається лише для HTTPS на loopback
  (агент ІІТ): власний CA агента, якщо знайдено, інакше `verify=False`; хост
  поза loopback ніколи не понижується (`iit_client._tls_verify`/`_request`).
- **Секрети не в git:** `config_local.toml`, `ansible/inventory/vault.yml`,
  `.vault_pass`, `Key-*.dat`, `*.pfx`/`*.p12`/`*.der`, захоплення `*.saz`,
  `downloads/`, `verified/` — у `.gitignore`. Бінарники ІІТ (`*.dll`,
  `*.exe`, `*.msi`, …) не комітяться ніде, у `tests/` теж: тестові PE
  будуються в пам'яті; в git — лише похідні метадані (`docs/inventory/`,
  `docs/DLL-REGISTRY.md`).
- **Тести не чіпають справжнього:** ні токена, ні агента, ні мережі —
  PyKCS11 фейковий, `requests`/`subprocess` підмінені; SoftHSM-токен
  інтеграційного тесту створюється у тимчасовому каталозі.
- **Імена документів СЕДО** перевіряються перед використанням у шляху
  (`_safe_doc_id`: без `..`, роздільників і зарезервованих імен Windows).
