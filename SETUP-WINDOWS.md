# Налаштування на Windows worker — покрокова інструкція

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.26
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

**Мета:** Запустити `sedo-client` на Windows машині з Алмаз-1К,
з Linux Ansible controller, за одну сесію (~2.5 години).

---

## Передумови

- Windows 10/11 x64
- Алмаз-1К USB підключено
- Адмін права для встановлення служб
- IIT "Користувач ЦСК-1" встановлено (DLL потрапляють у `C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\`)

---

## Крок 1: Перевірка Алмаз-1К (5 хв)

```powershell
# PowerShell з адмін правами

# 1.1 Smart Card service
Get-Service -Name SCardSvr
# Має бути Running. Якщо ні:
Set-Service -Name SCardSvr -StartupType Automatic
Start-Service -Name SCardSvr

# 1.2 Windows бачить пристрій
Get-PnpDevice -PresentOnly -Status OK |
  Where-Object { $_.FriendlyName -like "*Almaz*" -or $_.FriendlyName -like "*IIT*" }
# Очікуємо: FriendlyName = "IIT E.Key Almaz-1C"

# 1.3 ATR картки (через OpenSC якщо встановлено)
& "C:\Program Files\OpenSC Project\OpenSC\tools\opensc-tool.exe" --atr
# Очікуваний ATR: 3B 90 18 01 89
```

**Перевірити:** pnp device виведено, SCardSvr running, ATR читається.

---

## Крок 2: Python + OpenSC + залежності (15 хв)

```powershell
# 2.1 Python 3.11 або 3.12 (не 3.13 — PyKCS11 ще не підтримує)
winget install Python.Python.3.12
python --version  # 3.12.x

# 2.2 OpenSC — 32-bit варіант ОБОВ'ЯЗКОВО
# IIT DLL — 32-bit (PE32 I386), 64-bit pkcs11-tool НЕ зможе їх завантажити!
# Завантажити OpenSC-*-win32.msi (НЕ win64) з
# https://github.com/OpenSC/OpenSC/releases

# Перевірити що встановилось у правильне місце:
Test-Path "C:\Program Files (x86)\OpenSC Project\OpenSC\tools\pkcs11-tool.exe"
# Має бути True

# 2.3 Клієнт
cd C:\
git clone <repo> C:\sedo-client
cd C:\sedo-client
python -m venv venv
.\venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt
# Опційно, якщо плануєте pkcs11 backend замість opensc:
pip install PyKCS11
```

**Перевірити:** `pip list` показує `requests`, 32-bit OpenSC встановлено.

---

## Крок 3: Локація PKCS#11 DLL (5 хв)

Після встановлення IIT "Користувач ЦСК-1" PKCS11 DLL знаходиться у:

```
C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\
├── PKCS11.EKeyAlmaz1C.dll     (356 KB, 32-bit)
├── CSPBase.dll                (1.15 MB)
└── CSPExtension.dll           (80 KB)
```

`.cap` файли (параметри кривих) можуть бути розкидані по IIT директоріях:

```
C:\Program Files (x86)\Institute of Informational Technologies\Certificate Authority-1.3\End User\
C:\Program Files (x86)\Institute of Informational Technologies\Certificate Authority-1.3\End User\Web\
C:\Institute of Informational Technologies\Secure Connections-2\Client\
```

Скрипт `opensc-test-almaz.ps1` збирає всі cap-директорії автоматично і додає до PATH.

```powershell
# 3.1 Переконатись що PKCS11 DLL є
Test-Path "C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\PKCS11.EKeyAlmaz1C.dll"

# 3.2 Якщо пусто — переінсталювати IIT "Користувач ЦСК-1"
# https://iit.com.ua/download/productfiles/users
```

**Перевірити:** файл `PKCS11.EKeyAlmaz1C.dll` існує за цим шляхом.

---

## Крок 4: Повна валідація PKCS#11 (10 хв)

```powershell
# 4.1 Запустити головний тест (без PIN — безпечно)
cd C:\sedo-client
.\opensc-test-almaz.ps1

# Очікуваний вивід:
# [OK]  Знайдено: ...\EKeys\Almaz1C\PKCS11.EKeyAlmaz1C.dll
#       Бітність DLL: 32-bit
# [OK]   CSPBase.dll поруч
# [OK]   .cap файлів знайдено у 4 директоріях
# [OK]  pkcs11-tool.exe (32-bit): ...Program Files (x86)...
# Readers: IIT E.Key Almaz-1C 0
# ATR: 3B:90:18:01:89
# Cryptoki version 2.20, Library E.key_Almaz-1C_Library v1.0
# 12 mechanisms, включно з:
#   mechtype-0x80420031 keySize={163,509} hw sign verify EC F_2M   ← ДСТУ 4145
#   mechtype-0x80420032 keySize={163,509} hw sign verify EC F_2M   ← alt
```

**Перевірити:**
- Mechanism `0x80420031` присутній із flags `sign, verify, EC F_2M`
- Розмір ключа 163-509 біт (не 32 байти — 32 байти = симетричний)

---

## Крок 5: Перший тест підпису (10 хв)

⚠️ **КРИТИЧНО:** Алмаз знищує приватний ключ після 15 невдалих PIN.
Спочатку перевірте PIN вручну однією командою, і тільки потім автоматизуйте.

```powershell
# 5.1 Валідація PIN через запит об'єктів (1 невдача = 1 зі 15 лімітів)
.\opensc-test-almaz.ps1 -Pin XXXX

# Якщо успішно — побачите list-objects з сертифікатом

# 5.2 Тест підпису (виконає ОДИН --sign з mechanism 0x80420031)
.\opensc-test-almaz.ps1 -Pin XXXX -TestSign

# Очікуваний вивід:
# >>> mechanism 0x80420031 (IIT DSTU4145 primary):
# [OK]  sig-0x80420031.bin (64 bytes) -- ПРАЦЮЄ!
```

**Перевірити:** файл `sig-0x80420031.bin` створено, розмір 64-128 байт (DSTU 4145 підпис).

---

## Крок 6: Fiddler capture для SEDO auth (30 хв)

```powershell
# 6.1 Встановити Fiddler Classic (безкоштовний)
winget install Telerik.Fiddler.Classic
# або https://www.telerik.com/download/fiddler

# 6.2 Налаштувати перехоплення HTTPS
# Tools → Options → HTTPS → ✓ Decrypt HTTPS traffic
# Actions → Trust Root Certificate

# 6.3 Clear sessions (Ctrl+X), потім у Edge/Chrome відкрити:
#     https://sedo.mod.gov.ua/
# Пройти повну авторизацію ОДИН РАЗ вручну через "Користувач ЦСК"

# 6.4 Знайти у Fiddler запити:
#     - POST 127.0.0.1:8081/json-rpc    (виклики до IIT Agent)
#     - POST/GET *.sedo.mod.gov.ua/*     (API СЕДО)
#     - GET id.gov.ua/...                (якщо OIDC flow)

# 6.5 Експортувати сесію: File → Save → All Sessions
# Зберегти як sedo-auth-capture.saz

# 6.6 Запустити парсер
python scripts\fiddler_analyze.py sedo-auth-capture.saz
# Покаже послідовність викликів і тип flow:
# - OIDC через id.gov.ua
# - Direct KEP challenge-response
# - CMS POST
```

Див. `FIDDLER-CAPTURE-GUIDE.md` для детальної інструкції.

**Перевірити:** SAZ файл збережено, fiddler_analyze.py розпізнав flow.

---

## Крок 7: Інтеграція зі СЕДО (1 год)

Після Fiddler capture — оновити `_flow_*` методи в `sedo_client.py`
з точними URL і форматом JSON.

```powershell
# 7.1 Тестовий запуск
python sedo_client.py `
    --url https://sedo.mod.gov.ua `
    --backend opensc `
    --module "C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\PKCS11.EKeyAlmaz1C.dll" `
    --pin XXXX `
    -v

# 7.2 Повний цикл з завантаженням документів
python sedo_client.py `
    --url https://sedo.mod.gov.ua `
    --backend opensc `
    --module "...\PKCS11.EKeyAlmaz1C.dll" `
    --pin XXXX `
    --fetch `
    --output C:\sedo-client\downloads
```

**Перевірити:** авторизація успішна, документи завантажуються у `--output`.

---

## Крок 8: WinRM для Ansible (30 хв)

```powershell
# 8.1 Налаштування WinRM (як Administrator)
Enable-PSRemoting -Force
winrm quickconfig -transport:https
Enable-WSManCredSSP -Role Server -Force

# 8.2 SSL сертифікат
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME `
    -CertStoreLocation "cert:\LocalMachine\My"
# Додати HTTPS listener
New-Item -Path WSMan:\localhost\Listener `
    -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force

# 8.3 Firewall
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound `
    -LocalPort 5986 -Protocol TCP -Action Allow

# 8.4 Обмежений user для Ansible (БЕЗ адмін-прав!)
$pwd = Read-Host "Password for ansible_operator" -AsSecureString
New-LocalUser -Name "ansible_operator" -Password $pwd -Description "Ansible"
Add-LocalGroupMember -Group "Remote Management Users" -Member "ansible_operator"
```

```bash
# 8.5 Перевірка з Linux controller
ansible -i inventory/hosts.yml sedo_workers -m win_ping
# Має вивести: ws01 | SUCCESS => { "ping": "pong" }

# 8.6 Запуск playbook
cd /opt/sedo-client/ansible
ansible-playbook -i inventory/hosts.yml \
    playbooks/sedo_daily.yml \
    --ask-vault-pass
```

**Перевірити:** `win_ping` відповідає, playbook виконується успішно.

---

## Troubleshooting

### `sc_dlopen failed: LoadLibrary/GetProcAddress failed`

**Причина:** бітова несумісність — 64-bit `pkcs11-tool` не може завантажити 32-bit IIT DLL.

**Рішення:** встановити 32-bit OpenSC (див. Крок 2.2). Можна мати обидві версії паралельно.

### `Card is invalid or cannot be handled`

**Причина:** виникає при запуску `pkcs15-tool`, `opensc-explorer` або `pkcs11-tool` **без** `--module`.

**Рішення:** це нормально — Алмаз пропрієтарна картка IIT, native OpenSC driver її не розуміє. Працюйте ТІЛЬКИ через `pkcs11-tool --module PKCS11.EKeyAlmaz1C.dll`.

### Token info: `(token not recognized)`

**Причина:** OpenSC попереджає що не має PKCS#15 парсера.

**Рішення:** ігнорувати — попередження без наслідків. `--list-mechanisms`, `--login`, `--sign` працюватимуть через IIT DLL.

### `CKR_FUNCTION_NOT_SUPPORTED` при підписі

**Причина:** неправильний mechanism ID.

**Рішення:** перевірте `--list-mechanisms`, візьміть той де flags містять `sign, verify, EC F_2M` — це `0x80420031` або `0x80420032`. НЕ `0x80420014` (це MAC, не DSTU 4145).

### `CKR_PIN_LOCKED` / `USER_PIN_LOCKED`

**Причина:** PIN заблоковано або ключ знищено (15+ невдач).

**Рішення:** звернутись до ЦСК ЗСУ за новим ключем. Не варто пробувати ще раз — можна повністю добити.

### `Library not initialized` / `CKR_GENERAL_ERROR`

**Причина:** `CSPBase.dll` + `CSPExtension.dll` не поруч з PKCS11 DLL, або `.cap` файли не знайдено.

**Рішення:** скрипт `opensc-test-almaz.ps1` автоматично збирає .cap у PATH. Якщо ручний запуск — ось повна команда з PATH:

```powershell
$env:PATH = "C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C;" + `
            "C:\Program Files (x86)\Institute of Informational Technologies\Certificate Authority-1.3\End User;" + `
            $env:PATH
```

### `PyKCS11` не ставиться через pip

**Причина:** немає Visual C++ Build Tools.

**Рішення:** використати `opensc` backend замість `pkcs11` — він не потребує PyKCS11. Або:

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools
pip install PyKCS11
```

### Fiddler не перехоплює localhost (127.0.0.1:8081)

**Причина:** Windows за замовчанням не роутить localhost через проксі.

**Рішення:** у Fiddler OnBeforeRequest додати:
```javascript
oSession.host = "ipv4.fiddler:" + oSession.port;
```

---

## Контроль часу

| Крок | Час | Статус |
|---|---|---|
| 1. Перевірка Алмаз-1К | 5 хв | ☐ |
| 2. Python + 32-bit OpenSC | 15 хв | ☐ |
| 3. Локація PKCS#11 DLL | 5 хв | ☐ |
| 4. Валідація PKCS#11 | 10 хв | ☐ |
| 5. Перший підпис | 10 хв | ☐ |
| 6. Fiddler capture | 30 хв | ☐ |
| 7. Інтеграція SEDO | 60 хв | ☐ |
| 8. WinRM + Ansible | 30 хв | ☐ |
| **Всього** | **~2.5 год** | |

**Мілстоуни:**
- Після Кроку 4 — стек працює, mechanisms підтверджено
- Після Кроку 5 — підпис на токені працює
- Після Кроку 7 — повна SEDO авторизація
- Після Кроку 8 — автоматизація з Linux
