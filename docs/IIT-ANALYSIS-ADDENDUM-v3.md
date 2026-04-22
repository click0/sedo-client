# IIT-ANALYSIS — Addendum v3 (Crystal-1 Driver Package) 2026-04-22

> **Вхід:** повний пакет драйвера Crystal-1 — `EKeyCr1.cat`, `EKeyCr1.inf`, `EKeyCr1.dll` (32-bit), `EKeyCr164.dll` (64-bit), `EKeyCr1N.sys`, `HDPreinstall.exe`.
> **Призначення:** доповнення до v1/v2. Фокус — **kernel-mode driver** Crystal-1, VID/PID, correction до v1 addendum щодо 32-bit vs 64-bit варіантів.

---

## 0. TL;DR

1. 🔧 **Correction до v1 addendum §1 і §5:** файл, який я раніше вважав єдиним "EKeyCr1.dll (64-bit)", — насправді `EKeyCr164.dll`. Справжній 32-bit `EKeyCr1.dll` існує окремо (60 KB) і щойно отриманий. Пояснення найменування нижче.
2. 📦 **Crystal-1 — НЕ smartcard на рівні Windows**. ClassGuid у INF — звичайний USB (`36fc9e60-c465-11cf-8056-444553540000`), а не smart-card reader. Тому він **не бачиться через PC/SC/pcscd**.
3. 🏷️ **VID:PID = `03EB:9301`** (Atmel Corporation / Microchip chip).
4. 🛠️ Kernel driver `EKeyCr1N.sys` — стандартний WDM USB client, IRP + Power + Registry, **не CCID**. Використовує тільки 2 функції з `USBD.SYS`.
5. 🇺🇦 Code signer сертифікат вказує адресу `C=UA, ST=Kharkiv Oblast, L=Kharkiv, O=AT IIT, CN=AT IIT`. IIT зареєстрована у **Харкові**.
6. 🧱 Для sedo-client цей пакет **не потрібен** (Crystal-1 ≠ Алмаз-1К). Корисний, якщо хтось захоче писати Linux-драйвер для Crystal-1 — потрібен буде custom libusb-транспорт (не pcscd).

---

## 1. Correction до v1 addendum

У v1 addendum §1 я наводив таблицю:

| Файл як надіслано | OriginalFilename | Size | Machine |
|---|---|---|---|
| `EKeyCr1.dll` | `EKeyCr1.dll` | 69 120 | x64 |
| `EKeyCr1CCID.dll` | `EKeyCr1CCID.dll` | 125 968 | x64 |

**Це було неточно.** Файл 69 120 байт — це `EKeyCr164.dll`, а не `EKeyCr1.dll`. У IIT-пакеті:

```ini
[SourceDisksFiles]          ← 32-bit розділ
EKeyCr1.dll=3               ← source: EKeyCr1.dll (32-bit)

[SourceDisksFiles.amd64]    ← 64-bit розділ
EKeyCr164.dll=3             ← source: EKeyCr164.dll (64-bit)

[CopyDLL]                   ← куди встановлювати для 32-bit Windows
EKeyCr1.dll                 ← залишається EKeyCr1.dll

[CopyDLL_WOW64]             ← куди встановлювати 32-bit на 64-bit Windows
EKeyCr1.dll                 ← у SysWOW64

[CopyDLL64]                 ← куди встановлювати 64-bit на 64-bit Windows
EKeyCr1.dll,EKeyCr164.dll   ← dest=EKeyCr1.dll, source=EKeyCr164.dll
                              (тобто файл-джерело "EKeyCr164.dll" копіюється
                              під ім'ям "EKeyCr1.dll" у System32)
```

Тобто конвенція така:

| Середовище | Source filename | Installed to | Machine |
|---|---|---|---|
| IIT build tree | `EKeyCr1.dll` | `C:\Windows\SysWOW64\EKeyCr1.dll` (на 64-bit Win) | i386 |
| IIT build tree | `EKeyCr164.dll` | `C:\Windows\System32\EKeyCr1.dll` | amd64 |

Тому у вашому оригінальному XML-manifest:
```xml
<File>C:\Windows\SysWOW64\EKeyCr1.dll</File>     ← 32-bit (джерело: EKeyCr1.dll)
<File>C:\Windows\System32\EKeyCr1.dll</File>     ← 64-bit (джерело: EKeyCr164.dll)
```
обидва файли мають однакове ім'я на диску, але різну бітність. Я спочатку бачив тільки один файл і вважав його 64-bit варіантом — тепер отримав обидва.

**Виправлена таблиця:**

| Source filename | Size | SHA256 | Machine | FileVersion |
|---|---|---|---|---|
| `EKeyCr1.dll` (32-bit) | 60 416 | `8454d73a2a162d46c170501d99d20d927f0c5145a0d21e6e0391fceb3a278fe8` | i386 | 1.1.2.8 |
| `EKeyCr164.dll` (64-bit) | 69 120 | `eba73e280466546ab2a646e332871176ff6b5fe7c7d549a42b9503e74e893d69` | amd64 | 1.1.2.8 |

Обидва підтримують ті самі 56 експортів `C1*`. Семантика API ідентична.

---

## 2. Пакет драйвера — повний склад

| Файл | Розмір | Призначення | Machine | TimeStamp |
|---|---:|---|---|---|
| `EKeyCr1.inf` | 1 988 | INF-конфіг для Windows Driver Installer | — | — |
| `EKeyCr1.cat` | 10 910 | Authenticode catalog (PKCS#7) | — | — |
| `EKeyCr1N.sys` | 47 856 | **Kernel-mode WDM driver** | amd64 | 2021-06-09 |
| `EKeyCr1.dll` | 60 416 | User-mode бібліотека (32-bit) | i386 | 2018-06-20 |
| `EKeyCr164.dll` | 69 120 | User-mode бібліотека (64-bit) | amd64 | 2018-06-20 |
| `HDPreinstall.exe` | 47 104 | Мінімальний installer (SetupCopyOEMInf + SetupAPI queue) | amd64 | 2015-09-08 |

Різні timestamps є нормальним — kernel driver оновлюється окремо від user-mode обгортки, а installer — взагалі старий generic-утиліта що переиспользуется через версії.

---

## 3. `EKeyCr1.inf` — повна карта

Після декодування з **CP1251 (Windows Cyrillic)**:

```ini
[Version]
Signature = "$Chicago$"
Class = USB
ClassGuid = {36fc9e60-c465-11cf-8056-444553540000}
Provider = %Mfr%
DriverVer = 06/07/2021, 1.1.2.9
CatalogFile = EKeyCr1.cat

[Models]
%DeviceDesc% = EKeyCrystal1, USB\VID_03EB&PID_9301

[Models.ntia64]     ← так, ITANIUM підтримка
[Models.ntamd64]
```

Поля у `[Strings]`:
```
Mfr = "АТ ІІТ"
DriverDesc = "Драйвер електронного ключа Кристал-1"
DeviceDesc = "ІІТ Е.ключ Кристал-1"
```

### 3.1. Критично: Crystal-1 не CCID

ClassGuid `{36fc9e60-c465-11cf-8056-444553540000}` = **USB Device** (звичайний).

Для порівняння, CCID smart-card reader повинен мати один з:
- `{50DD5230-BA8A-11D1-BF5D-0000F805F530}` — Smart Card Reader class
- Або включати ще `DeviceInterfaceGUIDs` зі smart card GUID

Crystal-1 — **raw USB device**, керований власним драйвером IIT, а не generic CCID stack. Тому:
- ❌ не працює з `WinSCard.dll`
- ❌ не працює з `pcscd` + `libccid` на Linux
- ✅ працює через `EKeyCr1.dll` (обгортка над `DeviceIoControl` → `EKeyCr1N.sys` → `USBD.SYS` → хост-контролер)

**Виняток:** `EKeyCr1CCID.dll` з попереднього аналізу існує саме для випадку коли Crystal-1 **під'єднано через зовнішній CCID-ридер**. Тобто буває два фізичних варіанти Crystal-1: нативний USB (цей пакет), і smart-card чіп у ридері (обробляється через WinSCard). Це різні hardware, одна логіка на рівні C1*-API.

### 3.2. Service registration

```ini
[EKeyCrystal1_AddService]
DisplayName = "Драйвер електронного ключа Кристал-1"
ServiceType = 1          ; SERVICE_KERNEL_DRIVER
StartType = 3            ; SERVICE_DEMAND_START (не автостарт!)
ErrorControl = 0         ; SERVICE_ERROR_IGNORE
ServiceBinary = %10%\system32\drivers\EKeyCr1N.sys
```

`StartType=3` означає: драйвер стартує тільки коли пристрій фізично під'єднано (PnP-тригер через INF-match VID/PID).

### 3.3. Legacy Windows 9x/ME підтримка

INF містить дивний артефакт:
```ini
[SourceDisksFiles]
EKeyCr19.sys = 1     ; Windows 9x VxD?
```
і
```ini
[EKeyCrystal1_AddReg]
HKR,,DevLoader,,*NTKERN
HKR,,NTMPDriver,,EKeyCr19.sys
```

Це синтаксис реєстрації драйверу на Windows 9x/ME (з `DevLoader=*NTKERN` псевдо-loader). Файлу `EKeyCr19.sys` у пакеті немає. Ймовірно:
- Або IIT колись підтримував Windows 9x (~2003-2005) і залишок у INF досі присутній
- Або сучасний інсталер ігнорує цей розділ

Підтримка **Itanium (ia64)** також вказана (`[Models.ntia64]`), але `EKeyCr1N.sys` у пакеті тільки amd64. Знову — залишок від ширшої сумісності.

---

## 4. `EKeyCr1N.sys` — kernel-mode driver

| Поле | Значення |
|---|---|
| Size | 47 856 |
| Machine | AMD64 |
| Subsystem | **1 (native/kernel)** |
| Characteristics | 0x0022 (executable + large-address-aware, НЕ DLL) |
| Version | 1.1.2.9 |
| Build | 2021-06-09 12:39 UTC |
| PDB | `d:\hardware\ekeys\crystal1\revision1\programms\driver\objfre_wnet_amd64\amd64\EKeyCr1N.pdb` |

PDB-шлях підказує інструмент збірки: **`objfre_wnet_amd64`** = "free build (release), Windows Server 2003 WDK, amd64" — тобто зібрано старим [**Windows Server 2003 SP1 DDK (3790)**](https://en.wikipedia.org/wiki/Windows_Driver_Kit). Це пояснює довгу backward compatibility (Vista/7/8/10/11 всі підтримуються одним бінарником).

### 4.1. Imports (41 NT + 2 USBD)

`NTOSKRNL.exe`:
```
; Device stack
IoCreateDevice, IoDeleteDevice, IoAttachDeviceToDeviceStack, IoDetachDevice
IoRegisterDeviceInterface, IoSetDeviceInterfaceState

; IRP handling
IoAllocateIrp, IoFreeIrp, IofCallDriver, IofCompleteRequest
IoBuildDeviceIoControlRequest, IoInitializeRemoveLockEx
IoAcquireRemoveLockEx, IoReleaseRemoveLockEx, IoReleaseRemoveLockAndWaitEx

; Power management (WDM)
PoRequestPowerIrp, PoSetPowerState, PoStartNextPowerIrp, PoCallDriver

; Sync
KeInitializeEvent, KeSetEvent, KeClearEvent
KeWaitForSingleObject, KeWaitForMultipleObjects

; Worker threads
PsCreateSystemThread, PsTerminateSystemThread
IoAllocateWorkItem, IoFreeWorkItem, IoQueueWorkItem
ExInterlockedInsertTailList, ExInterlockedRemoveHeadList

; Memory
ExAllocatePool, ExFreePool

; Object mgmt
ObReferenceObjectByHandle, ObfDereferenceObject

; Registry
ZwOpenKey, ZwQueryValueKey, ZwClose

; Strings
RtlInitUnicodeString, RtlFreeUnicodeString
memcmp
```

`USBD.SYS`:
```
USBD_CreateConfigurationRequestEx       ; build SET_CONFIGURATION URB
USBD_ParseConfigurationDescriptorEx     ; parse descriptors
```

Класичний **WDM USB client driver**. Не CCID, не HID, не mass storage — сирий USB bulk/interrupt transport.

### 4.2. Відсутні у imports (для орієнтування)

- Немає `WdfXxx` — це **legacy WDM**, не Kernel-Mode Driver Framework (KMDF)
- Немає `USBD_SelectConfiguration`/`_SelectInterface` як окремих імпортів — вони викликаються через `IofCallDriver` з URB, а не напряму
- Немає `CcCopyRead`/`FsRtl*` — точно не файлова система

### 4.3. Архітектура драйвера (reconstructed)

Що робить драйвер у моменти життєвого циклу:

1. **DriverEntry** (не видно у strings, але стандартний pattern):
   - Реєструє dispatch routines для: `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_DEVICE_CONTROL`, `IRP_MJ_PNP`, `IRP_MJ_POWER`
2. **AddDevice**:
   - `IoCreateDevice` → створити FDO (Functional Device Object)
   - `IoAttachDeviceToDeviceStack` → над PDO від USB hub
   - `IoRegisterDeviceInterface` → створити symbolic link для user-mode (GUID знайти не вдалось у strings — ймовірно inline у `.text`)
3. **IRP_MJ_PNP / START_DEVICE**:
   - Створити URB через `USBD_CreateConfigurationRequestEx`
   - `USBD_ParseConfigurationDescriptorEx` → знайти pipe-и
   - `IofCallDriver` → передати URB нижче
   - `PsCreateSystemThread` → запустити worker thread (вірогідно, для обробки asynchronous bulk reads)
4. **IRP_MJ_DEVICE_CONTROL** (від user-mode `DeviceIoControl` з `EKeyCr1.dll`):
   - Обробити IOCTL, сконвертувати у URB, передати через IofCallDriver
   - IOCTL-коди не знайдено у strings — inline константи
5. **IRP_MJ_POWER**: стандартний pattern `Po*` з remove-lock sync

### 4.4. IOCTL коди — як дізнатися?

IOCTL у `EKeyCr1N.sys` **не витягуються через strings** — вони є 32-bit константи (`CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800+N, METHOD_BUFFERED, FILE_ANY_ACCESS)`) inline у `.text`. Щоб їх отримати, треба:

1. Відкрити `.sys` у IDA/Ghidra
2. Знайти dispatch-функцію `IRP_MJ_DEVICE_CONTROL` (через `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]` set у DriverEntry)
3. Переглянути switch-case на `IrpStack->Parameters.DeviceIoControl.IoControlCode`

Альтернатива: **динамічний trace**. Використати API Monitor на user-mode `DeviceIoControl` call-site у `EKeyCr1.dll` коли виконуються відомі C1*-операції (наприклад, `C1LogOn` з PIN). Побачити які IOCTL-коди передаються + які bulk-transfers ідуть через USB.

Для sedo-client це **не потрібно**. Для потенційного open-crystal-1 Linux драйвера — обов'язково.

---

## 5. `HDPreinstall.exe` — installer

Мінімальний GUI/console утиліта (Subsystem=2 = Windows GUI, але з основним функціоналом у `main`/`WinMain`):
- Читає `EKeyCr1.inf` через `SetupOpenInfFileA`
- Викликає `SetupCopyOEMInfA` — це **ядро driver installation**: копіює INF у `%windir%\inf\oem*.inf`, додає CAT у driver store
- Використовує `CRYPT32` для перевірки сертифікату каталогу (`CertOpenStore`, `CertAddEncodedCertificateToStore`)
- `CryptCreateHash` + `CryptHashData` — ймовірно, для хешування файлів перед інсталяцією

Timestamp 2015-09-08 — старіший за драйвер (2021). Це **generic IIT installer**, який пере-використовується між різними продуктами/оновленнями.

Для sedo-client: не потрібен (ви не інсталюєте драйвер з Python).

---

## 6. `EKeyCr1.cat` — Authenticode catalog

PKCS#7 SignedData. Ланцюг сертифікатів:

```
Signer: CN=AT IIT, O=AT IIT, L=Kharkiv, ST=Kharkiv Oblast, C=UA
  ↓ підписано
DigiCert SHA2 Assured ID Code Signing CA
  ↓
DigiCert Assured ID Root CA
  ↓ cross-signed to
Microsoft Code Verification Root                  ← дозволяє завантаження без WHQL

Timestamp: CN=DigiCert Timestamp 2021
  ↓
DigiCert SHA2 Assured ID Timestamping CA
  ↓
DigiCert Assured ID Root CA  →  Microsoft Code Verification Root
```

Два факти звідси:
1. **Видавець коду — AT IIT, фізично у Харкові** (за даними сертифікату; адреса могла бути зареєстрована у передвоєнний час, перевіряти з поточних публічних джерел якщо потрібно актуально)
2. **Cross-cert до Microsoft Code Verification Root** дозволяє драйверу завантажуватися на Windows 10/11 без WHQL-сертифікації (який дорожчий і повільніший). Це стандартна практика для вузькоспеціалізованих драйверів.

Catalog покриває 6 файлів (SHA1 entries):
- Один SHA1 збігається з вмістом `EKeyCr1.inf` — `e0db0da955ac7992d6a5022c85db696d88d03a61`
- Інші 5 — Authenticode hashes PE-файлів (не raw SHA1, тому прямо не співпадають з `sha1sum`). Ймовірно, покривають: `EKeyCr1.dll` (x86), `EKeyCr164.dll`, `EKeyCr1N.sys` (amd64), а також ia64 і/або x86 варіанти `.sys` які у пакеті відсутні.

---

## 7. Наслідки для sedo-client

### 7.1. Прямі

**Ніяких.** Пакет стосується Crystal-1, а sedo-client працює з Алмаз-1К. Два різних токени, різні API (`C1*` vs `C_*`).

### 7.2. Непрямі — уточнення документації

У вашому `SETUP-WINDOWS.md` / README варто додати FAQ-пункт:

> **Q: У мене токен "Кристал-1", а не "Алмаз-1К". Чи працює sedo-client?**
>
> A: Ні. sedo-client підтримує тільки Алмаз-1К через `PKCS11.EKeyAlmaz1C.dll`. Crystal-1 використовує власне API `C1*` з `EKeyCr1.dll` і не має PKCS#11-інтерфейсу у цьому пакеті. Теоретично можлива обгортка через `PKCS11.EKeyCrystal1.dll` (окрема DLL, у [IIT "Користувач ЦСК-1"](https://iit.com.ua/download/productfiles/users) повного інсталятора), але такий бекенд не реалізовано.

### 7.3. Потенційна користь для майбутнього

Якщо колись хтось захоче зробити **open-crystal-1** Linux-драйвер:

```
Linux libusb (user-mode)
       │
       │ USB VID=03EB PID=9301 (claim interface)
       │
       ▼
open-crystal.so  ← PKCS#11 2.40 facade
       │
       ├── Реалізувати C1*-еквіваленти через USB bulk/interrupt
       │   (IOCTL → URB mapping треба реверснути з EKeyCr1N.sys + trace)
       │
       └── udev rule: ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="9301",
                      MODE="0660", GROUP="plugdev"
```

Відсутність CCID-класу означає, що **PC/SC-підхід недоступний** — треба libusb напряму.

---

## 8. Оновлений hash-довідник

```
SHA256 — файли з усіх трьох addendum-ів:

# PKCS11 (Алмаз-1К)
3195e46a0f0e9b7e30fc0ae5bf06f9aeb93e1a37a5f9893e6082c3ca4365d53b  PKCS11.EKeyAlmaz1C.dll (HW, v1.0.1.7)
103a1b89b9f715f400b2a2b7e607ac689de9d33bd9129558cc377b19f94d4c61  PKCS11.Virtual.EKeyAlmaz1C.dll (v1.0.1.10)

# KM layer (Алмаз-1К)
03d34ac778737a895ec35197e0b8e4324705ba016e54b7ec91dc4f5a7f685765  KM.EKeyAlmaz1C.dll (v1.0.1.9)
f018b9aa710c602dedbe17399e3c4ad1263bd403a01513cd0a7bbc1ca08416ee  KM.EKeyAlmaz1CBTA.dll (v1.0.1.7, BLE variant)

# Crystal-1 (НЕ для sedo-client!)
8454d73a2a162d46c170501d99d20d927f0c5145a0d21e6e0391fceb3a278fe8  EKeyCr1.dll (32-bit, v1.1.2.8)   ← нове, 32-bit
eba73e280466546ab2a646e332871176ff6b5fe7c7d549a42b9503e74e893d69  EKeyCr164.dll (64-bit, v1.1.2.8) ← те що раніше мало неправильну назву у v1
a3e1e9237cb19f241367d5813969dd1b0af6fd75ec428b5bc73ba4809cb0a7a7  EKeyCr1CCID.dll (64-bit, v1.1.2.2)
dd20b4fe38dde8ed992672f425dda0cb6642240c35b77e1c64d7b967987ee382  EKeyCr1N.sys (kernel driver, v1.1.2.9)
7fa1c366813755e734c7a1baf83624aa72d4bed3fe38c08cfe3066743e93431a  EKeyCr1.inf
191a958c8804bc93df15c11f5712459792c657fa5b3ce12c10702311c15ef3be  EKeyCr1.cat
ebc3ab8bba72fbc723f89b434b341bc5cba9dd649e4a1bff9f689cf07d75f876  HDPreinstall.exe
```

---

## 9. Що все ще відсутнє (консолідований список з v1+v2+v3)

Для sedo-client (пріоритетне):
1. **`CSPBase.dll`**, **`CSPExtension.dll`**, **`PKIFormats.dll`** — спільні для HW і Virtual PKCS11 модулів Алмаз-1К
2. **`EUSignCP.dll`**, **`sCSPIBase.dll`** — для Virtual режиму Алмаз
3. **32-bit варіанти** усіх вище (для `opensc_signer.py`)
4. Тестовий `Key-6.dat` (для integration test Virtual-режиму)

Для довідки/архівації (не пріоритет):
5. **`PKCS11.EKeyCrystal1.dll`** — PKCS#11 обгортка для Crystal-1 (для повноти картини IIT-стеку)
6. **`EKeyCr19.sys`** (Windows 9x VxD — якщо ще існує, з історичною цінністю)
7. **Itanium варіант `EKeyCr1N.sys`** (теоретично є, у INF згаданий)

---

## 10. Метадані

- **Дата:** 2026-04-22
- **Версія addendum:** v3
- **Попередні:** v1 (основний), v2 (Virtual PKCS11)
- **Вхід:** EKeyCr1.{cat,inf,dll,dll64,sys}, HDPreinstall.exe — загалом 7 файлів, 233 197 байт
- **Формат INF:** CP1251 (не UTF-8/UTF-16) — якщо ви його коли-небудь парсуватимете програмно, не забудьте вказати encoding
