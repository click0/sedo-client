# TODO — стан ТЗ і що його охороняє

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.35
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

ТЗ (README «Що робить»): щоденний прогін без оператора — вхід у СЕДО ЗСУ
через КЕП, завантаження нових вхідних, верифікація підписів
`ua-sign-verify`, звіт. Нижче кожен крок, його стан і тест, який його тримає.
Нереалізоване має тест із `xfail(strict=True)` у `tests/test_sedo_contract.py`:
коли функцію зроблять, тест стане XPASS, CI впаде, маркер знімають — і тест
далі охороняє реалізацію.

## 1. Криптографія та вхід у токен — готово

| Що | Стан | Тести |
|---|---|---|
| Backend-и `opensc`, `pkcs11`, `virtual`, `iit_agent` | працюють | `test_opensc_*`, `test_pykcs11_api`, `test_virtual_signer`, `test_iit_client` |
| Справжній PKCS#11-стек | SoftHSM2 у CI (`integration-softhsm`) | `test_integration_softhsm` |
| Апаратний токен з PyKCS11 (`pkcs11`) | **не перевірено наживо** | потрібен `python sedo_client.py --check` з машини з токеном |
| Два ключі: `auth` / `sign`, `config_local.toml` | працює | `test_config`, `test_check` |
| Агент ІІТ: порти, Origin, AutoRun, TLS за CA | працює | `test_agent_tls`, `test_pin_safety` |

## 2. Вхід у СЕДО — чекає Fiddler-capture

| Крок | Стан | Тест |
|---|---|---|
| `_flow_direct_kep`: challenge → підпис → verify | працює проти здогаданих endpoint-ів; реальні невідомі | `TestDirectKEP` (локальний двійник), `TestEndToEnd` (SoftHSM) |
| Cookie з `verify` доходить до inbox/export | тримається | `TestDirectKEP::test_authorize_then_fetch_then_download` |
| Відмова сервера ≠ успіх | тримається | `TestDirectKEP::test_rejection_is_never_a_success` |
| PIN не потрапляє в HTTP | тримається | `TestDirectKEP::test_flows_do_not_leak_the_pin` |
| `_flow_oidc`: танець id.gov.ua | **повертає False** | `TestOIDCAhead` (xfail) |
| `_flow_cms_post`: CAdES/CMS SignedData | **NotImplementedError**; потрібен ще builder CMS, бо signer-и дають сирий r‖s | `TestCMSAhead` (xfail) |

Що зняти Fiddler-ом: `FIDDLER-CAPTURE-GUIDE.md`. Після capture — заповнити
`docs/sedo-flow.md`, оновити `EXPECTED` і двійник у `test_sedo_contract.py`.

## 3. Документи — шляхи здогадані

| Крок | Стан | Тест |
|---|---|---|
| `fetch_inbox` (`/api/documents/inbox?since=`) | шлях здогаданий; `since` передається | `TestDirectKEP`, `test_sedo_client::TestFetchInbox` |
| Прострочена сесія → помилка, не «0 документів» | тримається | `TestSessionExpiry::test_inbox_without_session_raises` |
| Пагінація (`next`) | працює за здогаданою схемою: рядок `next` (відносний чи абсолютний) лише на тому ж хості, без циклів, до 100 сторінок; без `next` — як раніше | `TestInboxPagination` (обидва файли тестів) |
| `download_document` (`/api/documents/<id>/export`) | шлях здогаданий; ZIP пишеться як `<id>.zip` | `TestDirectKEP`, `test_sedo_client::TestDownloadDocument` |
| Перевірка тіла (HTML замість ZIP при протухлій сесії) | працює: HTML і порожня відповідь відхиляються, не-ZIP зберігається з попередженням | `TestSessionExpiry::test_download_of_a_non_document_is_rejected`, `test_expired_session_redirect_to_login_is_rejected`, `test_cli_stops_on_an_html_export` |
| Підпис документа всередині СЕДО ключем `sign` | **не реалізовано**; `sign` працює лише через `--sign-file` | `TestDocumentSigningAhead` (xfail) |

## 4. Контракт з Ansible — тримається

| Що | Тест |
|---|---|
| `changed_when` обох playbook-ів шукає `Документів: [1-9]` у stdout | `TestCLIContract::test_fetch_prints_what_the_playbook_parses` |
| Playbook-и передають лише прапорці, які знає парсер | `TestCLIContract::test_playbooks_only_pass_flags_the_parser_knows` |
| 0 документів — не `changed` | `TestCLIContract::test_zero_documents_is_not_changed` |
| Верифікація `ua-sign-verify` на контролері: виклик однаковий в обох плейбуках, код 0 — валідний, 1 — попередження, інше — помилка; відсутній верифікатор — «не перевірено», а не «помилки підписів»; падіння (код 1 + traceback) — помилка | `TestVerifierContract`, `TestBuildReport` |

## 5. Звіт — готово

| Що | Стан | Тест |
|---|---|---|
| Telegram-звіт (`telegram.bot_token` / `chat_id` у `vault.yml`) | працює: `sedo/telegram_report.py`, крок наприкінці обох плейбуків | `tests/test_telegram_report.py` |
| Провал воркера не зупиняє плейбук до верифікації і звіту | працює: `block`/`rescue` у play воркера, помилка прогону — останнім кроком | `TestPlaybookFailureFlow` |
| Недосяжний воркер теж: вимкнений на старті або обрив посеред прогону | працює: `wait_for_connection` першим у block, `localhost`-якір у play воркера, `lost_workers` у звіті | `TestUnreachableWorker` |

## Порядок, коли буде capture

1. `python scripts/fiddler_analyze.py sedo_login_reference.saz --output fiddler_report.txt`
   (лише структура, значення замасковано, звіт можна передавати) → `docs/sedo-flow.md`.
2. `EXPECTED` і маршрути двійника в `tests/test_sedo_contract.py` → реальні.
3. `_flow_*` / шляхи API / схема пагінації (`fetch_inbox`) в `sedo/client.py`;
   зняти `xfail` там, де тест став XPASS.
4. `python sedo_client.py --check` і прогін з `-v` на машині з токеном.
