# CHANGELOG

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
License:  BSD 3-Clause "New" or "Revised" License
```

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
