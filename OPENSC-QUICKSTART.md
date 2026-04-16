# OpenSC Quickstart — через IIT PKCS#11 module

**⚠️ Важливо:** Алмаз-1К — пропрієтарна картка IIT. OpenSC **не має вбудованого драйвера** для неї,
тому `pkcs15-tool`, `opensc-explorer` і інші tools що читають картку напряму **не працюватимуть**.

Ви бачитимете:
```
Failed to connect to card: Card is invalid or cannot be handled
```

Це **нормально**. Використовуйте тільки `pkcs11-tool --module <IIT_DLL>`.

---

## Архітектура

```
OpenSC pkcs11-tool.exe
     │
     │ --module PKCS11_EKeyAlmaz1C.dll
     ▼
[PKCS#11 API] ← стандартний C-interface
     │
     ▼
IIT PKCS11_EKeyAlmaz1C.dll ← знає внутрішню структуру Алмаза
     │ + CSPBase.dll + *.cap
     ▼
WinSCard → Алмаз-1К
```

OpenSC тут — **універсальний клієнт**, IIT DLL — **адаптер до картки**.

---

## Швидка перевірка (без PIN)

```powershell
$DLL = "C:\Program Files (x86)\Institute of Informational Technologies\ЄвроЗнак\PKCS11_EKeyAlmaz1C.dll"
$TOOL = "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe"

# Reader (це OpenSC вміє — через PC/SC, без драйвера картки)
& "C:\Program Files\OpenSC Project\OpenSC\tools\opensc-tool.exe" --list-readers

# Info про модуль
& $TOOL --module $DLL --show-info
# Очікуємо: Manufacturer: JSC_IIT, Library: E.key_Almaz-1C_Library

# Слоти та токени
& $TOOL --module $DLL --list-slots
# Очікуємо: Slot 0: label=E.key_Almaz-1C_Slot

# ⭐ Механізми — підтвердить 0x80420014
& $TOOL --module $DLL --list-mechanisms
```

## З PIN (обережно!)

```powershell
# ⚠️ 15 невдалих спроб → Алмаз знищить ключ!

& $TOOL --module $DLL --login --pin XXXX --list-objects

# Експорт сертифіката
& $TOOL --module $DLL --login --pin XXXX `
    --read-object --type cert --id 01 `
    --output-file cert.der

# Переглянути сертифікат через стандартні Windows tools
certutil -dump cert.der
```

## Тест підпису

```powershell
"hello" | Out-File -FilePath data.txt -Encoding ASCII -NoNewline

# Спочатку спробувати IIT vendor mechanism
& $TOOL --module $DLL --login --pin XXXX `
    --sign --mechanism 0x80420014 `
    --input-file data.txt --output-file sig.bin

# Якщо не спрацювало — стандартний CKM_DSTU4145
& $TOOL --module $DLL --login --pin XXXX `
    --sign --mechanism 0x00000352 `
    --input-file data.txt --output-file sig.bin
```

## Що НЕ потрібно робити

| Команда | Чому не працює |
|---|---|
| `pkcs15-tool --list-pins` | OpenSC не має драйвера Алмаза |
| `pkcs15-tool --dump` | Те саме |
| `opensc-explorer` | Те саме |
| `eidenv` | Для eID карток, не Алмаз |
| `pkcs11-tool --list-slots` (БЕЗ --module) | OpenSC використає built-in — не знає Алмаз |

## Використання в sedo-client

Три backend на вибір:

```powershell
# OpenSC (subprocess до pkcs11-tool) — простий, не потребує PyKCS11
python sedo_client.py --backend opensc `
    --module "C:\...\PKCS11_EKeyAlmaz1C.dll" `
    --pin XXXX --fetch

# PyKCS11 (Python binding) — швидше
python sedo_client.py --backend pkcs11 `
    --module "C:\...\PKCS11_EKeyAlmaz1C.dll" `
    --pin XXXX --fetch

# IIT Agent (JSON-RPC) — fallback
python sedo_client.py --backend iit_agent --pin XXXX --fetch
```

## Чому все одно варто мати OpenSC

Навіть якщо pkcs15-tool не працює, OpenSC корисний:

1. **`pkcs11-tool`** — стандартний універсальний клієнт для будь-якого PKCS#11 модуля
2. **`opensc-tool --list-readers`** — діагностика PC/SC
3. **Знайомий інструмент** — є у всіх дистрибутивах Linux, Windows admin toolkit
4. **`pkcs11-register`** — реєстрація PKCS#11 модулів у Firefox, Thunderbird, Chrome автоматично

## Reference: повна сесія тестування

```powershell
# ═══════════════════════════════════════════════════════════════
# Повна сесія валідації Алмаз-1К + IIT PKCS#11
# ═══════════════════════════════════════════════════════════════

$DLL  = "C:\Program Files (x86)\Institute of Informational Technologies\ЄвроЗнак\PKCS11_EKeyAlmaz1C.dll"
$PATH = "C:\Program Files\OpenSC Project\OpenSC\tools"
$PIN  = Read-Host "PIN" -AsSecureString |
        ConvertFrom-SecureString -AsPlainText

# 1. Reader видно?
& "$PATH\opensc-tool.exe" --list-readers

# 2. Module завантажується?
& "$PATH\pkcs11-tool.exe" --module $DLL --show-info

# 3. Токен є?
& "$PATH\pkcs11-tool.exe" --module $DLL --list-slots

# 4. Які mechanisms?
& "$PATH\pkcs11-tool.exe" --module $DLL --list-mechanisms

# ❗ ТОЧКА НЕПОВЕРНЕННЯ — з цього моменту використовуємо PIN
# Збережіть reference значення показу mechanisms для 0x80420014

# 5. Об'єкти
& "$PATH\pkcs11-tool.exe" --module $DLL --login --pin $PIN --list-objects

# 6. Сертифікат
& "$PATH\pkcs11-tool.exe" --module $DLL --login --pin $PIN `
    --read-object --type cert --id 01 --output-file almaz-cert.der

# 7. Підпис (ONLY щоб підтвердити що ключ реально працює)
"validation" | Out-File -FilePath val.txt -Encoding ASCII -NoNewline
& "$PATH\pkcs11-tool.exe" --module $DLL --login --pin $PIN `
    --sign --mechanism 0x80420014 `
    --input-file val.txt --output-file val.sig

# Успіх якщо:
# - val.sig існує
# - Розмір ~64 bytes (DSTU 4145-257 signature)
# - Команда завершилась без помилок
```
