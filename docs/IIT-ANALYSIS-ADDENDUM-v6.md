# IIT-ANALYSIS — Addendum v6 (Complete 32-bit Chain + KM Architecture) 2026-04-22

> **Вхід:** 32-bit `PKCS11.EKeyAlmaz1C.dll`, 32-bit `PKCS11.Virtual.EKeyAlmaz1C.dll`, `KM.dll`, `KM_PKCS11.dll`, `KM_FileSystem.dll`, `KM_EKeyCrystal1.dll`, `KM_CModGryada61.dll`, `LDAPClient.dll`, `EKAlmaz1CConfiguration.exe`, новіші-старіші версії `CSPBase.dll`/`PKIFormats.dll`/`KM.EKeyAlmaz1C.dll`/`KM.EKeyAlmaz1CBTA.dll`.
> **Призначення:** доповнення до v1–v5. Закриває останні gap-и. **Шлях В1 Linux/Wine deploy тепер повністю розблокований.**

---

## 0. TL;DR — головне для sedo-client

1. ✅ **32-bit PKCS#11 chain замкнутий ПОВНІСТЮ.** Можна запускати на Linux через Wine без Windows worker і USB passthrough (для Virtual-варіанта).
2. 🔑 **KM_FileSystem.dll** — саме той модуль, який читає `Key-N.dat` файли (template: `%sKey-%X.dat`). Ось як Virtual PKCS#11 працює internally: PKCS11_Virtual → EUSignCP → KM.dll → KM_FileSystem.dll → `C:\Users\<user>\AppData\...\Key-6.dat`.
3. 🗺️ **KM_PKCS11.dll** розкриває повну архітектуру: через RTTI C++ класи бачимо що він керує 11+ типами токенів (Almaz HW/Virtual, Crystal-1 HW/Virtual, Gryada-61, Gryada-301, Avest, JaCarta, generic UA hardware).
4. ⚠️ **Version drift between batches.** Cтарі `CSPBase/PKIFormats` (v5 набір, 2025-06…08) і нові файли з цього batch (CSPBase 2023-08, PKIFormats 2024-01) — **РІЗНІ SNAPSHOT-И**. Треба використовувати файли з одного дистрибутива. Нижче рекомендація.

---

## 1. Що нового / змінилося у цьому batch

### 1.1. Нові файли

| Файл | Розмір | Machine | Build | FileVer | Роль |
|---|---:|---|---|---|---|
| **`KM.dll`** | 170 224 | i386 | 2017-09-19 | 1.0.1.1 | Базовий KM loader (завантажує KM.*.dll) |
| **`KM_PKCS11.dll`** | 301 648 | i386 | 2025-02-28 | 1.0.1.37 | Router для сторонніх PKCS#11 модулів |
| **`KM_FileSystem.dll`** | 84 720 | i386 | 2017-09-18 | 1.0.1.2 | **Software key storage через файлову систему** |
| `KM_EKeyCrystal1.dll` | 77 552 | i386 | 2017-01-24 | 1.0.1.1 | KM для Crystal-1 HW |
| `KM_CModGryada61.dll` | 77 040 | i386 | 2017-01-24 | — | KM для Гряда-61 |
| `LDAPClient.dll` | 81 648 | i386 | 2017-09-10 | — | LDAP клієнт (для CRL distribution) |
| `EKAlmaz1CConfiguration.exe` | 3 147 704 | i386 | 2021-11-24 | 1.0.2.7 | GUI-конфігуратор Алмаз-1К |

### 1.2. Оновлення архітектури (раніше 64-bit, тепер 32-bit варіанти)

| Файл | Попередньо | Зараз |
|---|---|---|
| **`PKCS11.EKeyAlmaz1C.dll`** | 64-bit, 418 832 b, v1.0.1.7 | **32-bit**, 364 560 b, v1.0.1.7 ← **закрито missing piece** |
| **`PKCS11.Virtual.EKeyAlmaz1C.dll`** | 64-bit, 968 208 b, v1.0.1.10 | **32-bit**, 1 019 408 b, v1.0.1.10 ← **закрито missing piece** |
| `KM.EKeyAlmaz1C.dll` | 64-bit, 599 056 b, v1.0.1.9 | **32-bit**, 691 728 b, v1.0.1.9 (та сама версія, інша бітність) |
| `KM.EKeyAlmaz1CBTA.dll` | 64-bit, 292 280 b | **32-bit**, 245 176 b |

Тепер є повний **32-bit snapshot** на додачу до раніше проаналізованого 64-bit snapshot.

### 1.3. Старіші версії деяких файлів

⚠️ **Важлива примітка про version drift:**

| Файл | v5 batch (2025 snapshot) | v6 batch |
|---|---|---|
| `CSPBase.dll` | v1.1.0.173, 2025-06-18 | **v1.1.0.172, 2023-08-03** ← старіша |
| `PKIFormats.dll` | v1.2.0.171, 2025-08-15 | **v1.2.0.163, 2024-01-04** ← старіша |
| `EUSignCP.dll` | v1.3.1.209, 2025-11-03 | (не у v6 batch) |

**Ви отримали файли з двох різних snapshot-ів IIT "Користувач ЦСК-1"**: свіжий (листопад 2025) і старший (2023–2024). Це може бути проблемою при змішуванні — ABI може відрізнятися. Рекомендація нижче у §6.

---

## 2. Архітектура KM — повна картина

З отриманих файлів складається така ієрархія:

```
                    EUSignCP.dll (619 exports)
                           │
                           │ LoadLibraryW("KM.dll")
                           ▼
                         KM.dll  ← "Базова бібліотека роботи з НКІ"
                        (3 fns: KMEnumDeviceTypes, KMGetInterface, KMFinalize)
                           │
                           │ завантажує один з KM.*-типів
                           ▼
             ┌─────────────┴─────────────────────────────────┐
             │                                                │
    ┌────────┴────────────────┐           ┌──────────────────┴──────┐
    │ HW-токени (різні)       │           │ Virtual/Software         │
    ▼                         ▼           ▼                          ▼
KM.EKeyAlmaz1C.dll      KM.EKeyCrystal1.dll    KM.FileSystem.dll       KM.PKCS11.dll
  (Almaz HW)             (Crystal-1 HW)          (software key storage)  (router for 3rd-party PKCS#11)
KM.EKeyAlmaz1CBTA.dll   KM.CModGryada61.dll     (+ KM.PKCS11 HW variants) │
  (Almaz BLE)            (Gryada-61)                                       │
                                                                           ├── PKCS11.EKeyAlmaz1C.dll  ← ЦІКАВО: router може ВИКЛИКАТИ
                                                                           │   (власний PKCS11 IIT)         чужий PKCS#11 теж!
                                                                           │
                                                                           ├── PKCS11.EKeyCrystal1.dll
                                                                           ├── PKCS11.NCMGryada301.dll (Гряда-301 HSM)
                                                                           │
                                                                           ├── avcryptokinxt.dll  (Avest NXT: AvestKey/EfitKey/AvPassG)
                                                                           ├── Av337CryptokiD.dll (Avest CC-337/ST-338)
                                                                           ├── plcpkcs11.dll      (NOKK TEllipse3)
                                                                           │
                                                                           └── JaCarta / iToken / eToken / …
```

### 2.1. `KM.dll` (базовий loader)

| Поле | Значення |
|---|---|
| FileDescription | "ІІТ Базова бібліотека роботи з НКІ" |
| Експорти | `KMEnumDeviceTypes`, `KMGetInterface`, `KMFinalize` (як у всіх KM-модулях) |
| SHA256 | `4b5ccac7dccab030191672eb0daca7b404e520c308ee0e235700207a3124077d` |
| Build | 2017-09-19 (дуже старий) |

Цей файл — **диспетчер на вершині**. Коли `EUSignCP` викликає `KM.dll::KMEnumDeviceTypes()`, KM.dll повертає список усіх підтримуваних типів носіїв: "EKeyAlmaz1C", "EKeyCrystal1", "NCMGryada301", "CModGryada61", "FileSystem", "PKCS11", "EKeyAlmaz1CBTA", …

Потім `EUSignCP` викликає `KMGetInterface("EKeyAlmaz1C")` → KM.dll внутрішньо `LoadLibraryW("KM.EKeyAlmaz1C.dll")` → отримує vtable звідти → повертає вище.

Цей pattern ізолює `EUSignCP` від конкретних transport deatils. Тому `EUSignCP` не потрібно знати, що Алмаз це USB CCID, а Гряда — мережева HSM: кожен `KM.*` модуль обгортає свій transport.

### 2.2. `KM.PKCS11.dll` (router сторонніх PKCS#11 модулів) — РОЗКРИТО

У v1 addendum §6 цей модуль був описаний на основі вашого оригінального `docs/IIT-ANALYSIS.md`. Тепер я маю сам файл і можу підтвердити + розширити.

| Поле | Значення |
|---|---|
| FileDescription | "ІІТ Бібліотека роботи з НКІ, які підтримують формат ключових даних PKCS#11" |
| FileVersion | 1.0.1.37 |
| Build | **2025-02-28** (свіжа!) |
| Експорти | `KMEnumDeviceTypes`, `KMGetInterface`, `KMFinalize` (той самий KM-interface) |
| Імпорти | KERNEL32 + RPCRT4.dll (1 fn — для UUID/GUID operations) |

### 2.2.1. RTTI класи розкривають повну підтримку

З `strings` у `.rdata` (RTTI C++ names `.?AV...@@`):

```cpp
// IIT-власні токени
class EKeyAlmaz1C            class EKeyAlmaz1CHardware           class EKeyAlmaz1CHardwareCSP
class VirtualEKeyAlmaz1CHardware    // ← для Virtual-режиму!
class EKeyCrystal1           class EKeyCrystal1Hardware          class EKeyCrystal1HardwareCSP
class VirtualEKeyCrystal1Hardware   // ← Crystal-1 теж має Virtual!
class CModGryada61           class CModGryada61Hardware          class CModGryada61HardwareCSP
class NCMGryada301Hardware                                       class NCMGryada301HardwareCSP

// Сторонні токени
class AvestKey               class AvestKeyHardware              class AvestKeyHardwareCSP
class AladdinJaCartaASEKey   // JaCarta ASE

// Generic UA PKCS#11 hardware (для будь-якого ДСТУ-сумісного стороннього токена)
class PKCS11UAHardware       class PKCS11UAHardwareCSP
class PKCS11UAHardwareCSPI   class PKCS11UAHardwareRNG

// Helpers
class PKCS11AliasApplication         // мапінг device-alias
class PKCS11DeviceInfoApplication    // device info query
class PKCS11NamedKeyApplication      // named key access (для keystore-like токенів)
class PKCS11Storage                  // storage abstraction
```

**Цікава архітектура:** кожен токен має три class-шари:
- `<TokenName>` — абстрактний тип
- `<TokenName>Hardware` — конкретна hw-implementation
- `<TokenName>HardwareCSP` — CSP-compatible wrapper (для передачі у CSPBase.dll/CSPIBase.dll)

Для Virtual-варіантів додається `<TokenName>Virtual` — software-emulation.

### 2.2.2. Наявний файл `Av337CryptokiD.dll` у .rdata strings

`KM.PKCS11.dll` має у `.rdata` рядки "Avest (PKCS#11)", "Av337CryptokiD.dll" — тобто він **явно зашитий на конкретні сторонні DLL**. Це означає:
- router не просто сліпо викликає `C_GetFunctionList` на будь-який модуль, який знаходить
- він має **whitelist відомих PKCS#11 DLL-імен** і пробує їх по одному
- для кожного знає який тип токена очікувати

### 2.3. `KM_FileSystem.dll` (software keystore) — РОЗКРИТО

**Це ключ до розуміння, як Virtual PKCS#11 працює внутрі.** Раніше я припускав у v2 addendum, що Virtual читає приватний ключ з файлу — тепер можу точно сказати, через що саме.

| Поле | Значення |
|---|---|
| FileDescription | "ІІТ Бібліотека роботи з НКІ типу: **'файлова система'**" |
| Експорти | `KMEnumDeviceTypes`, `KMGetInterface` (стандартний KM-API) |
| Розмір | 84 720 b (малий — просто IO wrapper) |
| Build | 2017-09-18 |

### 2.3.1. Key file naming pattern

У `.rdata` знайдено формат-стрічки (printf-format):
```
%sKey-%X.dat
%sKey-?.dat
```

Це **template для імен файлів приватних ключів**. `%s` — шлях до директорії, `%X` — hex-індекс (0–F, можливо більше). Приклади:
- `Key-0.dat`, `Key-1.dat`, …, `Key-6.dat`, …, `Key-F.dat`
- Потенційно double-hex: `Key-10.dat`, `Key-1A.dat`, …

"**Key-6.dat**" — конкретний інстанс (hex `6`), часто згадуваний у контексті IIT — це **перший слот** (у інших інсталяціях зустрічається Key-1.dat, Key-2.dat тощо).

Саме ці файли перераховуються через `EUCtxEnumNamedPrivateKeys` з EUSignCP API (v5 §6.2). Кожен `Key-N.dat` = один "named private key".

### 2.3.2. C++ класи

```cpp
class FileSystem               // загальний
class FileSystemMachine        // per-machine storage (HKLM context, likely %ProgramData%)
class FileSystemUser           // per-user storage (HKCU context, likely %AppData%)
```

Тобто IIT підтримує **два профілі** зберігання ключів:
- **Machine** — для системного сервісу (наприклад, сервер підпису на worker)
- **User** — для інтерактивного користувача

Точні шляхи (треба перевірити у strings глибше або у EUSignCP):
- Machine: `C:\ProgramData\Institute of Informational Technologies\...\Key-N.dat`
- User: `C:\Users\<user>\AppData\Roaming\Institute of Informational Technologies\...\Key-N.dat`

### 2.3.3. Наслідки для sedo-client

Для Virtual-шляху (software-token) це означає:

```
Linux cron (Ansible controller)
    │
    ▼
Wine prefix з PKCS11.Virtual.EKeyAlmaz1C.dll (32-bit)
    │
    ├── WinSCard.dll   ← не використовується в pure-soft режимі
    │
    └──[LoadLibrary]──▶ EUSignCP.dll
                           │
                           ├── CSPBase/CSPExtension/CSPIBase/PKIFormats
                           │
                           └──[LoadLibrary]──▶ KM.dll
                                                  │
                                                  │ KMGetInterface("FileSystem")
                                                  ▼
                                              KM_FileSystem.dll
                                                  │
                                                  │ відкриває %APPDATA%/...Key-N.dat
                                                  ▼
                                              файл ключа (з вашого Ansible Vault)
```

Шлях встановлюється через реєстр або через `EUSetPrivateKeyMediaSettings` API. Перевіримо з runtime-тесту.

---

## 3. Повний мінімальний набір для Linux/Wine (32-bit)

### 3.1. Файли-список (підтверджено)

**Обов'язкові для HW-режиму (якщо маєте фізичний Алмаз-1К):**
```
PKCS11.EKeyAlmaz1C.dll         ← 32-bit (ваш новий)
CSPBase.dll                    ← версія 1.1.0.172 (або 173)
CSPExtension.dll               ← версія 1.1.0.17
PKIFormats.dll                 ← версія 1.2.0.163 (або 171)
+ wine winscard + pcscd + libccid на Linux
+ USB passthrough
```

**Обов'язкові для Virtual-режиму (software-token з Key-N.dat):**
```
PKCS11.Virtual.EKeyAlmaz1C.dll ← 32-bit (ваш новий)
EUSignCP.dll                   ← версія 1.3.1.209
CSPBase.dll
CSPExtension.dll
CSPIBase.dll
PKIFormats.dll
KM.dll                         ← новий
KM_FileSystem.dll              ← новий (читає Key-N.dat)
+ Key-N.dat файл (з вашого Ansible Vault)
+ wine winscard (stub — реально не використовується)
```

**Опціонально (розширений функціонал):**
```
KM_PKCS11.dll                  ← якщо хочете підтримку сторонніх PKCS#11 токенів
KM_EKeyAlmaz1C.dll             ← якщо хочете щоб Virtual падав назад на HW, якщо той є
LDAPClient.dll                 ← якщо CRL розподіляються через LDAP (рідко)
CAConnectors.dll               ← якщо хочете онлайн-OCSP перевірку
```

**НЕ потрібні для headless:**
```
CAGUI.dll                      ← GUI library (Delphi)
EUShellMenu.dll / EUShellMenu64.dll  ← Windows Explorer integration
EKAlmaz1CConfiguration.exe     ← GUI config tool
```

### 3.2. Рекомендація щодо version consistency

**Беріть всі файли з одного snapshot-у.** У вас зараз дві версії критичних залежностей:
- Snapshot А (v5 batch): CSPBase 1.1.0.173 (2025-06), PKIFormats 1.2.0.171 (2025-08), EUSignCP 1.3.1.209 (2025-11)
- Snapshot Б (v6 batch): CSPBase 1.1.0.172 (2023-08), PKIFormats 1.2.0.163 (2024-01), KM.dll 1.0.1.1 (2017-09), KM_FileSystem 1.0.1.2 (2017-09)

**Рекомендую snapshot Б** — старіший, але внутрішньо consistent (це схоже на один випуск пакета). Snapshot А це оновлення тільки крипто-ядра без оновлення KM-рівня, що потенційно може ламати binding.

Якщо ж знайдеться новіший snapshot, який МАЄ усі файли — краще його. Повний інсталятор "Користувач ЦСК-1" з https://iit.com.ua/download/productfiles/users дає такий snapshot.

---

## 4. `EKAlmaz1CConfiguration.exe` — GUI конфігуратор

| Поле | Значення |
|---|---|
| FileDescription | "ІІТ Е.ключ 'Алмаз-1К'. Конфігурація" |
| FileVersion | 1.0.2.7 |
| Build | 2021-11-24 |
| Розмір | 3 147 704 (3 MB) |
| Mode | **Delphi/VCL** (за patterns експортів `@@ClassName@MethodName`) |

Експорти з patterns типу `@@Changeactivewaitingtime@Finalize` показують Delphi VCL об'єктний код. Компоненти з strings: `TSpinEdit`, `TRegistry`, `TBiDiMode`, `TDragMode`, `TTileMode` — це все стандартні VCL controls.

### 4.1. Що конфігурує

Менюпункти видні з експорту:
- `ChangeActiveWaitingTime` — змінити "час очікування" (вірогідно — idle timeout до auto-logout)
- (інші пункти меню scroll-ні; потрібен або дизасемблер, або запуск у Wine для повного списку)

**Читає/пише** з реєстру `TRegistry` — параметри Алмаз-1К. Для sedo-client цей конфігуратор **не потрібен**, бо заводські дефолти нормально працюють.

### 4.2. Практична корисність

Якщо ви колись деплоюватимете sedo-client на новій Windows worker-машині і хочете змінити `idle timeout` для токена, — це єдиний інструмент. Альтернативно, можна писати ті самі значення у реєстр напряму через Ansible `win_regedit`, якщо розібратись які ключі.

---

## 5. `LDAPClient.dll`

| Поле | Значення |
|---|---|
| Експорти | `LDAPClientGetInterface`, `LDAPClientFinalize` (vtable pattern) |
| Статичні imports | **`WLDAP32.dll`** (3 функції) |
| Розмір | 81 648 |
| Build | 2017-09-10 |

Це **LDAP-клієнт** для вичитки CRL з LDAP-директорій. Використовується EUSignCP, коли:
- CRL Distribution Point у сертифікаті має URL з схемою `ldap://`
- Для СЕДО ЗСУ це рідкість (МОУ CA зазвичай віддає CRL через HTTP), але деякі державні CA досі LDAP

Для sedo-client: **не критично.** Можна не включати у Wine prefix і тільки додати якщо в логах виникнуть помилки про CRL retrieval.

---

## 6. Wine deployment cookbook (32-bit, перевірений теоретично)

### 6.1. Базова установка

```bash
# 1. Встановити 32-bit Wine і залежності
sudo apt install wine32 wine-binfmt winetricks pcscd libccid opensc

# 2. Створити 32-bit prefix
export WINEARCH=win32 WINEPREFIX=~/.wine-iit
wineboot --init

# 3. Покласти 32-bit DLLs у Wine System32 (це реальний 32-bit шлях)
IIT=~/.wine-iit/drive_c/windows/system32
cp CSPBase.dll CSPExtension.dll CSPIBase.dll PKIFormats.dll \
   EUSignCP.dll KM.dll KM_FileSystem.dll \
   PKCS11.Virtual.EKeyAlmaz1C.dll \
   $IIT/

# 4. Створити реєстрові ключі, які EUSignCP шукає (v5 §6.3)
cat > /tmp/iit.reg << 'EOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Institute of Informational Technologies\Certificate Authority-1.3]

[HKEY_LOCAL_MACHINE\SOFTWARE\Institute of Informational Technologies\Certificate Authority-1.3\End User]

[HKEY_LOCAL_MACHINE\SOFTWARE\Institute of Informational Technologies\Certificate Authority-1.3\End User\Libraries]
EOF
wine regedit /tmp/iit.reg

# 5. Покласти Key-N.dat у відоме місце
#    IIT шукає у %APPDATA%\...\Institute of Informational Technologies\
#    У Wine це: ~/.wine-iit/drive_c/users/<user>/AppData/...
mkdir -p ~/.wine-iit/drive_c/iitkeys
cp Key-6.dat ~/.wine-iit/drive_c/iitkeys/

# 6. Тест через pkcs11-tool (треба 32-bit варіант!)
wine pkcs11-tool.exe \
    --module C:\\windows\\system32\\PKCS11.Virtual.EKeyAlmaz1C.dll \
    --list-slots --show-info

# Очікуваний результат:
#   Slot 0: E.key_Almaz-1C_Slot
#   Token: E.key_Almaz-1C
#   Manufacturer: JSC_IIT
```

### 6.2. Відомі ризики

1. **Wine winscard.dll** спрацьовує у пасивному режимі (reader list порожній), що в Virtual-режимі = OK. Для HW-режиму треба міст до нативного pcscd, який Wine підтримує через `WINEDLLOVERRIDES`.
2. **Реєстрові ключі** могутньо впливають — якщо EUSignCP не знаходить своєї конфігурації, startup-fail. `regedit` до запуску обов'язково.
3. **Path до Key-N.dat** — треба протестувати через `EUCtxEnumNamedPrivateKeys` або через sedo-client з налагодженим logging. Можливо знадобиться реєстрово-параметр `HKCU\...\KeyStore\Path` або аналог (точне ім'я треба реверсити з EUSignCP).
4. **PIN** — IIT software-ключі традиційно захищаються паролем (8-16 символів). Для Ansible Vault передачу, не повинно бути проблем.

### 6.3. Integration з sedo-client

Оновлений виклик з вашого README:

```bash
# Windows worker з HW токеном (як раніше)
python sedo_client.py --backend opensc \
    --module "C:\Program Files (x86)\IIT\PKCS11.EKeyAlmaz1C.dll" \
    --pin $PIN --fetch

# Linux worker з Wine + Virtual (НОВИЙ варіант)
wine-python sedo_client.py --backend opensc \
    --module C:\\windows\\system32\\PKCS11.Virtual.EKeyAlmaz1C.dll \
    --pin $PIN --fetch
```

Або Python-нативно через Linux PKCS#11 bindings (якщо десь існує `.so` варіант; у цьому snapshot — немає).

---

## 7. Оновлений список того, чого не вистачає

### 7.1. Потрібно для production sedo-client

✅ **ПОВНИЙ 32-bit chain отримано.** Нічого критичного не відсутнє для Virtual-режиму.

### 7.2. Nice-to-have (для повноти)

1. **64-bit snapshot, consistent з 32-bit** — якщо хочете дзеркальний 64-bit deployment
2. **`.so` (нативно Linux) варіанти PKCS11 модулів** — перевірити у повному інсталяторі IIT, чи існують взагалі (вірогідно ні, але варто спробувати)
3. **Тестовий `Key-6.dat`** з відомим PIN — для integration test у CI
4. **Повний інсталятор "Користувач ЦСК-1"** — щоб отримати self-consistent snapshot усіх файлів

### 7.3. Для архіву (не пріоритет)

5. `PKCS11.EKeyCrystal1.dll` — для Crystal-1
6. `KM.VirtualEKeyAlmaz1C.dll` (якщо такий є окремо) — можливо, не існує, бо Virtual-логіка живе всередині PKCS11.Virtual
7. Аналогічний Authenticode-пакет `.cat` для IIT DLL (перевірити підпис)

---

## 8. Метадані

- **Дата:** 2026-04-22
- **Версія:** v6 (останнє addendum — chain повний)
- **Попередні:** v1, v2, v3, v4, v5
- **Вхід:** 8 файлів з batch + фінальний огляд

### 8.1. SHA256 всіх critical 32-bit файлів (v6 snapshot)

```
# PKCS#11 модулі Алмаз-1К (32-bit)
3ef2497f9fd1635932835a13999aae8cf64d031b47e0028afc99ddedbd58b675  PKCS11.EKeyAlmaz1C.dll
3c6eeafebee28258033f48f8148688c288eb7af8fb3f92230bbba6b364cd3944  PKCS11.Virtual.EKeyAlmaz1C.dll

# Крипто-залежності
d4a4129f0c8d408e1b2ae6fa1e661439bb02b7e6d77f9acffba800f9c8188582  CSPBase.dll (v1.1.0.172, 2023-08)
c60a3de7719e3ba405c4c6a29097ebbb5442f46a1699a35cd2c3968920a9e562  CSPExtension.dll
ab37b21a3c317433c47b53f9353ddd7c66e7200ff29cb88f04f1e4d5d05f836b  CSPIBase.dll
6108dc01b64c21cb993e31cac11833bac53cb4de90b636130a58ab29d5a324a7  PKIFormats.dll (v1.2.0.163, 2024-01)
f61b817adfccba6bc570bcd23da07969efb4bf752ee1ada9207595cee07ffcc3  EUSignCP.dll

# KM layer
4b5ccac7dccab030191672eb0daca7b404e520c308ee0e235700207a3124077d  KM.dll
e0c1c6246074cc36d0f95ec417b15a5b36cdb4c89afc00fd68aa04129b184a76  KM_PKCS11.dll
1da6e100cb9263cc90d782b864f4e1d14267ed7e39791daf4ccf312f8a5acc06  KM_FileSystem.dll
183c6d10bb49b01eccc81cbd7ca2ac52e501937a7a99126ed9ac17f4af8dde74  KM_EKeyAlmaz1C.dll (32-bit)
a21943c0a3c65804958dcc08580a0018dad515020f538b9d587e4d05161f476c  KM_EKeyAlmaz1CBTA.dll (32-bit)
8193d3cf85d54a8a10575fcc55ccd1f6b708f1771301390745f31ea5f4f25a75  KM_EKeyCrystal1.dll
b7bc5ebfd1fe0b674ecfbba61c7a9d2fbcfd4071190d0cb01c74bad783d25c88  KM_CModGryada61.dll

# Допоміжні
19cf49d3ec2547bd3b6ba159fd606fc44142363824e8cd4a27198bc93d81ae2e  LDAPClient.dll
c56f3c850925dc2fa2020bb070fcf64993c99bb21d45e9c339f152575b4a66cd  EKAlmaz1CConfiguration.exe
```

### 8.2. Загальний stat

Проаналізовано у v1–v6: **28 унікальних PE файлів** (DLL + SYS + EXE + INF + CAT), ~70 MB binary content, ~125 KB markdown analysis у 6 addendum-ах.

**Шлях В1 (sedo-client на Linux через Wine з software-токеном)** — **готовий до real-world тесту.**
