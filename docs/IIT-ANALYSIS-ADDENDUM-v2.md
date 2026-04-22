# IIT-ANALYSIS — Addendum v2 (Virtual PKCS11) 2026-04-22

> **Вхід:** `PKCS11.Virtual.EKeyAlmaz1C.dll` (968 KB) + повторно `PKCS11.EKeyAlmaz1C.dll` (той самий, SHA256 збігається — ігнорується).
> **Призначення:** доповнення до `IIT-ANALYSIS-ADDENDUM.md` v1. Фокус — порівняння **HW** vs **Virtual** PKCS#11 варіантів.

---

## 0. Summary

**Virtual — це НЕ просто "емулятор без HW".** Це повний software-token, який:

- Експортує **той самий PKCS#11 2.40 ABI** (ті самі 68 `C_*` символів), тобто **drop-in сумісний** з OpenSC / PyKCS11 / pkcs11-provider
- **Реалізує всі 68 функцій** (жодного CKR_FUNCTION_NOT_SUPPORTED stub-а — на відміну від HW-варіанта, де заглушено Encrypt/Decrypt/Recover/GenerateKey)
- Читає приватний ключ **з файлу** (Key-6.dat, PFX/PKCS#12) через `EUSignCP.dll`
- Все одно статично імпортує `WinSCard.dll` — тобто може **також працювати з реальним HW**, якщо той присутній (dual-mode)

**Для sedo-client це змінює архітектуру:** на Linux-worker можна запускати Virtual через Wine **без прокидання USB-токена**. Ключ лежить у файлі (з шифруванням паролем), що ідеально для Ansible Vault-автоматизації.

---

## 1. Ідентифікація

| Поле | HW варіант | Virtual варіант |
|---|---|---|
| Файл | `PKCS11.EKeyAlmaz1C.dll` | **`PKCS11.Virtual.EKeyAlmaz1C.dll`** |
| SHA256 | `3195e46a0f0e9b7e30fc0ae5bf06f9aeb93e1a37a5f9893e6082c3ca4365d53b` | **`103a1b89b9f715f400b2a2b7e607ac689de9d33bd9129558cc377b19f94d4c61`** |
| Розмір | 418 832 | 968 208 |
| .text (код) | 282 562 b | **728 962 b** (× 2.58) |
| FileVersion | 1.0.1.7 | **1.0.1.10** (новіша) |
| Build | 2023-02-02 | **2024-05-23** |
| OriginalFilename (VS) | `PKCS11.EKeyAlmaz1C.dll` | `PKCS11.EKeyAlmaz1C.dll` *(!)* |
| Export table DLL name | `PKCS11.EKeyAlmaz1C.dll` | **`PKCS11.Virtual.EKeyAlmaz1C.dll`** |
| PDB | `…\EKeyAlmaz1C\x64\Release\PKCS11\PKCS11EKeyAlmaz1C64.pdb` | **`…\EKeyAlmaz1C\Virtual\x64\Release\PKCS11VirtualEKeyAlmaz1C.64.pdb`** |

**Цікаво:** у VS_VERSIONINFO Virtual помилково вказує `InternalName = PKCS11.EKeyAlmaz1C.dll` (без "Virtual"). Фактична ідентифікація йде **за ім'ям файлу, яке кладе інсталятор**, і за PDB-шляхом у `.rdata`. Експорт-таблиця Virtual-версії при цьому правильно каже `PKCS11.Virtual.EKeyAlmaz1C.dll`.

---

## 2. ABI різниця — реалізованість функцій

Обидва DLL експортують **68 функцій C_***. Але у HW-варіанті стуб за RVA `0x0000f510` (байти `b8 54 00 00 00 c3` — `mov eax, 0x54; ret` = CKR_FUNCTION_NOT_SUPPORTED) розділений між 20+ функціями. У Virtual — **кожна функція має унікальну адресу, жодних stub-ів.**

| Функція | HW | Virtual |
|---|---|---|
| C_Initialize/Finalize/GetInfo/GetFunctionList | ✅ | ✅ |
| C_GetSlotList/Info, GetTokenInfo, GetMechanismList/Info | ✅ | ✅ |
| C_Login/Logout, OpenSession/CloseSession | ✅ | ✅ |
| C_FindObjectsInit/FindObjects/Final | ✅ | ✅ |
| C_GetAttributeValue / SetAttributeValue | ✅ | ✅ |
| **C_Sign / SignInit / SignUpdate / SignFinal** | ✅ | ✅ |
| C_Verify / VerifyInit / VerifyUpdate / VerifyFinal | ✅ | ✅ |
| C_Digest / DigestInit / DigestUpdate / DigestFinal | ✅ | ✅ |
| C_DeriveKey (ECDH) | ✅ | ✅ |
| C_WrapKey / UnwrapKey | ✅ | ✅ |
| C_GenerateRandom / SeedRandom | ✅ | ✅ |
| **C_Encrypt / EncryptInit / EncryptUpdate / EncryptFinal** | ❌ stub | ✅ |
| **C_Decrypt / DecryptInit / DecryptUpdate / DecryptFinal** | ❌ stub | ✅ |
| **C_GenerateKey / GenerateKeyPair** | ❌ stub | ✅ |
| C_SignRecover / VerifyRecover | ❌ stub | ✅ |
| C_DigestEncryptUpdate / DecryptDigestUpdate / SignEncryptUpdate / DecryptVerifyUpdate | ❌ stub | ✅ |
| C_GetOperationState / SetOperationState | ❌ stub | ✅ |
| C_CopyObject | ❌ stub | ✅ |
| C_WaitForSlotEvent | ❌ stub | ✅ |
| C_CancelFunction | — (reused) | ✅ (унікальна, RVA `0x00023fe0`) |

Підтвердження: з групування адрес експорту, у Virtual **усі 68 функцій мають різні адреси**.

**Наслідок:** якщо комусь потрібен повний PKCS#11 API (наприклад, для шифрування документів у СЕДО при надсиланні) — HW-варіант цього не дасть, Virtual — дасть.

---

## 3. Транспорт і залежності

### 3.1. Статичні імпорти

| DLL | HW | Virtual |
|---|---|---|
| KERNEL32.dll | 87 функцій | **92 функції** |
| ADVAPI32.dll | 5 | 5 (ідентичні: InitializeSD, SetSDDacl, EventLog) |
| WinSCard.dll | **8 функцій** (SCardTransmit, etc.) | **8 функцій — ті самі** |

WinSCard статично присутній в обох. У Virtual це означає, що він **також може опитувати USB-токен через PC/SC**, якщо той присутній. Логіка runtime-вибору (HW присутній → використати; відсутній → soft-fallback на файл) лежить у `.text` секції та у функції `EUIsHardwareKeyMedia` (яка вантажиться з EUSignCP.dll).

### 3.2. Runtime LoadLibrary-залежності (те, що не видно у статичних imports)

| DLL | HW варіант | Virtual варіант |
|---|---|---|
| `CSPBase.dll` | ✅ | ✅ |
| `CSPExtension.dll` | ✅ | ✅ |
| `PKIFormats.dll` | ✅ | ✅ |
| **`EUSignCP.dll`** | ❌ | **✅** ← головна крипто-бібліотека IIT |
| **`sCSPIBase.dll`** | ❌ | **✅** ← Software CSP Implementation Base |

Тобто мінімальний набір файлів **збільшується на 2 DLL** для Virtual-варіанта.

Різниця у кількості `EU*` рядків у `.rdata`:
- HW: **0** (не викликає EUSignCP)
- Virtual: **455** різних `EU*` символів, які resolve-ляться через `GetProcAddress(EUSignCP, ...)`

Серед них — "файлові" та "software-key" API:

```
EUCtxReadPrivateKeyFile                         ← читання ключа з файлу
EUCtxReadNamedPrivateKey                        ← читання named keystore
EUCtxEnumNamedPrivateKeys                       ← перелік named ключів
EUCtxIsNamedPrivateKeyExists
EUCtxGenerateNamedPrivateKey                    ← генерація software-ключа
EUCtxGetNamedPrivateKeyInfo
EUCtxDestroyNamedPrivateKey
EUCtxChangeNamedPrivateKeyPassword
EUCtxExportPrivateKeyContainerFile              ← експорт у IIT-контейнер
EUCtxExportPrivateKeyPFXContainerFile           ← експорт у PFX (PKCS#12)
EUChangeSoftwarePrivateKeyPassword              ← зміна пароля на софт-ключ
EUIsHardwareKeyMedia                            ← runtime-перевірка HW vs soft
EUEnumKeyMediaDevices + EUEnumKeyMediaTypes     ← перелік носіїв
EUGetKeyMediaDeviceInfo / EUFreeKeyMediaDeviceInfo
EUSetKeyMediaPassword / SetKeyMediaUserPassword
EUGetPrivateKeyMedia / EUGetPrivateKeyMediaEx / EUGetPrivateKeyMediaSettings
EUSetPrivateKeyMediaSettings / EUSetPrivateKeyMediaSettingsProtected
EUProtectDataByPassword / EUUnprotectDataByPassword  ← шифрування паролем
```

### 3.3. PBKDF / KDF для файлового keystore

У `.rdata` Virtual (але **не** HW):
```
PBKDF2DeriveKey / PBKDF2SelfTest                ← RFC 2898
PBKDF2IDeriveKey / PBKDF2ISelfTest              ← IIT variant
PBKDFMACDeriveKey / PBKDFMACSelfTest
PKCS12PBKDFSHA1DeriveHMACKey                    ← PKCS#12 класичний
PKCS12PBKDFTDESDeriveKey / DeriveIV             ← PKCS#12 для 3DES
PKCS12PBKDFRC2DeriveKey / DeriveIV              ← PKCS#12 для RC2
PKCS12PBKDFDSTU7564DeriveKey                    ← PKCS#12 + Купина (IIT extension)
PKCS5PBKDF2DSTU7564DeriveKey                    ← PBKDF2 + Купина (IIT extension)
```

Це підтверджує: Virtual **може читати стандартні PFX-файли** з PBKDF2+3DES (як openssl pkcs12), а **також IIT-ні Key-6.dat** що використовують PBKDF2+DSTU 7564 (Купина).

### 3.4. `sCSPIBase.dll` — що це

Нова DLL якої не було ні у HW, ні у вашому попередньому аналізі. У `.rdata` Virtual-модуля вона супроводжується RTTI-класами:
- `.?AVCSPI@@` — Software CSP Implementation (інтерфейс)
- `.?AVCSPIParameters@@` — параметри для нього

Ім'я `sCSPIBase` (зі стрічкової літери "s") = "**s**oftware **CSPI** **Base**" — базовий шар software-CSP. Містить ймовірно:
- Читання/запис контейнерів приватних ключів на диску
- Обгортка над PBKDF2 для розшифровки
- Кеш відкритих ключів у процесі

Це ще один файл, який потрібно додати у MINIMUM-FILES-LIST для Virtual-режиму.

---

## 4. Оновлений мінімальний набір файлів

### Для HW-варіанта (Алмаз-1К фізичний токен):
```
PKCS11.EKeyAlmaz1C.dll
CSPBase.dll
CSPExtension.dll
PKIFormats.dll
+ WinSCard.dll (OS)
+ pcscd (Linux)
+ libccid (Linux)
+ USB access до токена
```

### Для Virtual-варіанта (software-token, Key-6.dat у файлі):
```
PKCS11.Virtual.EKeyAlmaz1C.dll
EUSignCP.dll                    ← НОВА залежність
sCSPIBase.dll                   ← НОВА залежність
CSPBase.dll
CSPExtension.dll
PKIFormats.dll
+ файл приватного ключа (Key-6.dat / *.pfx / *.p12)
+ WinSCard.dll (для statically linked imports, але можна stub-замінити; реально HW не потрібен)
```

Нагадування: всі файли мають бути **однієї бітності**. 64-bit process → 64-bit DLL chain.

---

## 5. C++ класи — відмінність від HW

Virtual має **усі 37 RTTI класів HW-варіанта** + два додаткові:

```
PKCS11VirtualEKeyAlmaz1C        ← верхівка virtual-обгортки
CSPI                             ← software CSP interface (из sCSPIBase)
CSPIParameters                   ← параметри для CSPI
```

Опечатка `PKCS11TokenCotext` (Cotext замість Context) — присутня в обох, бо спільні templates.

---

## 6. Архітектурні наслідки для sedo-client

### 6.1. Спрощення Linux-деплою (шлях В1)

**Було (HW-варіант):**
```
Linux host
├── Wine prefix
│   ├── PKCS11.EKeyAlmaz1C.dll
│   ├── CSPBase.dll + CSPExtension.dll + PKIFormats.dll
│   └── Wine winscard.dll → libpcsclite.so
├── pcscd + libccid (сервіс)
└── USB passthrough (або фізичний порт) ← нетривіально для контейнера/VM
```

**Стає (Virtual-варіант):**
```
Linux host
├── Wine prefix
│   ├── PKCS11.Virtual.EKeyAlmaz1C.dll
│   ├── EUSignCP.dll + sCSPIBase.dll                ← новачки
│   └── CSPBase.dll + CSPExtension.dll + PKIFormats.dll
├── файл Key-6.dat (з Ansible Vault)
└── НЕ потрібно USB, pcscd, libccid
```

Це радикально простіше для контейнеризації, CI, і для випадку коли Windows worker взагалі не потрібен.

### 6.2. Безпека

**Плюси Virtual-шляху:**
- Ключ у файлі можна зашифрувати паролем з Ansible Vault
- Немає 15-спробного ліміту PIN (HW Алмаз-1К знищує ключ після 15 помилок — це ризик для cron без людини)
- Бекап тривіальний (копія файлу)

**Мінуси:**
- Файл ключа може бути вкрадений → пароль стає єдиним bаr'єром → brute-force можливий офлайн
- Для роботи з СЕДО ЗСУ може бути **нормативне обмеження** на software-токени (перевірити з адміністратором СЕДО!)
- Кваліфікована ЕЦП (КЕП) за законодавством України для державних органів може вимагати QSCD-сертифікованого носія (HW Алмаз-1К такий, software keystore — ні)

### 6.3. Рекомендація

Для `sedo-client` пропоную **підтримати обидва варіанти**:

```python
# sedo_client.py --backend virtual
python sedo_client.py \
    --backend opensc \
    --module "C:\Program Files (x86)\IIT\PKCS11.Virtual.EKeyAlmaz1C.dll" \
    --key-file "C:\keys\Key-6.dat" \
    --pin "$PIN" \
    --fetch
```

Додати у README.md новий рядок у таблицю backends:

| Backend | Pros | Dependency |
|---|---|---|
| `opensc` (HW) | Найпростіший, QSCD-compliant | 32-bit OpenSC + HW Алмаз-1К |
| `opensc` (Virtual) | **Не потрібен USB-токен, CI-friendly** | Key-6.dat файл + EUSignCP.dll |
| `pkcs11` | Швидший | OpenSC + PyKCS11 + HW |
| `iit_agent` | Без OpenSC | IIT Користувач ЦСК GUI |

### 6.4. Тестовий сценарій

1. Скопіювати всі 6 DLL у Wine prefix:
   ```
   PKCS11.Virtual.EKeyAlmaz1C.dll
   EUSignCP.dll  sCSPIBase.dll
   CSPBase.dll  CSPExtension.dll  PKIFormats.dll
   ```
2. Скопіювати Key-6.dat у доступний з Wine шлях
3. Запустити:
   ```bash
   wine pkcs11-tool.exe \
       --module ~/.wine/drive_c/iit/PKCS11.Virtual.EKeyAlmaz1C.dll \
       --list-slots
   # очікуваний slot: "E.key_Almaz-1C_Slot"
   
   wine pkcs11-tool.exe --module ... --list-mechanisms
   # має показати 12+ mechanisms, включно з 0x80420031 (DSTU 4145 sign)
   
   wine pkcs11-tool.exe --module ... --login --pin XXXX --list-objects
   # має показати: приватний ключ + сертифікат з Key-6.dat
   ```

Якщо це спрацює — Windows worker з USB-токеном більше не потрібен.

---

## 7. Непаримарні деталі

### 7.1. Authenticode

Обидва DLL підписані (Security Directory розмір: **10 256 байт, однаковий**). Обидва мають referenci на DigiCert CA в `.rdata`. Virtual додатково реферує новіші endpoint-и:
- `DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt`
- `DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt`
- `DigiCertTrustedRootG4.crt`

→ Virtual-підпис новіший (SHA384 code signing, G4 root). Це очікувано, бо build 2024-05 vs 2023-02.

### 7.2. Mutex sharing

Обидва DLL використовують **ті самі іменовані Mutex-и**:
- `Global\EKAlmaz1COpenMutex`
- `Global\EKAlmaz1CMutex`
- `Global\EKAlmaz1CMemory`
- `Global\EKAlmaz1CKeysMemory`

Це означає, що **одночасний запуск HW і Virtual на одній системі буде блокуватися взаємно** через ці mutex-и. На практиці — це не проблема (обирається один варіант), але варто знати.

### 7.3. Той самий PKCS#11 slot-name

Обидва DLL видають слот під ім'ям `E.key_Almaz-1C_Slot` і токен `E.key_Almaz-1C`. Код sedo-client не мусить змінюватися між бекендами — достатньо змінити шлях до `--module`.

### 7.4. Шлях збірки у PDB

Різні release-trees, але спільний батьківський каталог:
```
D:\Hardware\KeyMedias\EKeyAlmaz1C\x64\Release\PKCS11\...      ← HW
D:\Hardware\KeyMedias\EKeyAlmaz1C\Virtual\x64\Release\...     ← Virtual
```

Цікаво, що Virtual НЕ має підпапки `PKCS11\` у своєму шляху (проти HW, де є). Мінорна деталь, але підтверджує, що Virtual вважається самостійним продуктом у дереві IIT, а не просто opt-варіантом PKCS11-модуля.

---

## 8. Запропоновані правки у репо — доповнення до v1 addendum

**`docs/IIT-ANALYSIS.md`:**
- Оновити §6 "KM.PKCS11.dll router table": статус `PKCS11.Virtual.EKeyAlmaz1C.dll` з "Віртуальний (без HW)" на "Віртуальний/soft-token. ✅ Отримано. Drop-in з HW-варіантом через однаковий PKCS#11 ABI. Повний набір C_* функцій."
- Додати §12 "HW vs Virtual порівняння" з таблицею з §2 цього файлу

**`docs/MINIMUM-FILES-LIST.md`:**
- Розділити на два списки: "HW-варіант" та "Virtual-варіант"
- У Virtual додати `EUSignCP.dll` та `sCSPIBase.dll`

**`README.md` / `README_uk.md`:**
- У таблицю backends додати рядок Virtual
- У секцію Security додати згадку про QSCD-обмеження для КЕП на державному рівні

**Новий файл `docs/VIRTUAL-TOKEN.md`:**
- Інструкція для налаштування Virtual-режиму
- Де взяти Key-6.dat (у користувача у "Користувач ЦСК-1")
- Як експортувати PFX з IIT-GUI і використати у sedo-client

**`SETUP-WINDOWS.md`:**
- Додати опційний розділ "Без фізичного токена": як використати Virtual варіант

---

## 9. Що все ще не вистачає (оновлений список)

1. **`CSPBase.dll`, `CSPExtension.dll`, `PKIFormats.dll`** — обов'язкові для обох варіантів
2. **`EUSignCP.dll`** — обов'язкова для Virtual
3. **`sCSPIBase.dll`** — обов'язкова для Virtual (нова знахідка у v2)
4. **32-bit варіанти всіх перелічених** — для `opensc_signer.py` через 32-bit OpenSC
5. Тестовий Key-6.dat файл (для integration test)
6. Повний інсталятор IIT "Користувач ЦСК-1" — щоб підтвердити, що всі ці файли туди входять і довідатися їхні імена у інсталі

---

## 10. Метадані

- **Дата:** 2026-04-22
- **Версія addendum:** v2
- **Попередня:** v1 (`IIT-ANALYSIS-ADDENDUM.md` від 2026-04-22)
- **Вхід:** `PKCS11_Virtual_EKeyAlmaz1C.dll` (968 208 b, SHA256 `103a1b89b9f715f400b2a2b7e607ac689de9d33bd9129558cc377b19f94d4c61`)
- **Файли проігноровано як дублікати:** `PKCS11_EKeyAlmaz1C.dll` (той самий, що вже проаналізований у v1)
