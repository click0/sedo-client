# Методологія реверс-інжинірингу IIT бібліотек

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Version:  0.29
License:  BSD 3-Clause
Year:     2025-2026
```

## Мета

Документ описує методологію і інструменти, використані для аналізу закритих
бібліотек ІІТ "Користувач ЦСК". Це дозволяє іншим:

1. Повторити наші висновки для перевірки
2. Оновити аналіз коли IIT випустить нові версії DLL
3. Застосувати ті самі техніки для інших закритих українських PKI-бібліотек

## Використані інструменти

| Інструмент | Призначення |
|---|---|
| `objdump` (binutils) | Експорти, імпорти, секції PE |
| `strings` | Текстові constants в бінарці |
| `LIEF` (Python) | Структурний аналіз PE, метадані |
| Python + `struct` | Розпарсити PE header, знайти arrays в .data |
| `grep`, `awk` | Фільтрація великих dumps |
| `file` | Ідентифікація архітектури (PE32 vs PE32+) |
| `scripts/iit_inventory.py` | **Наш** stdlib-інвентаризатор: версії, sha256, експорти/імпорти, LoadLibrary-залежності, DWORD-лічильники mechanism ID, diff між snapshot-ами, реєстр (`docs/DLL-REGISTRY.md`) |
| `scripts/iit_unpack.sh` | Розпакування інсталяторів без запуску: `msiextract` (msitools), `innoextract`, `cabextract`, `7z` |
| `pefile` (Python, опційно) | Cross-check нашого парсера: `pip install .[analysis]`, `--engine pefile` |

## Категорії бінарок IIT

Входом був `Web.zip` пакет — 36 DLL + 9 `.cap` файлів (параметри кривих).

### Фронт-енд (HTTP сервери)
| DLL | Розмір | Роль |
|---|---|---|
| `EUSignAgent.dll` | 159 KB | Локальний HTTP/HTTPS сервер, Mongoose |
| `NCHostCP.dll` | 1.5 MB | CA Gateway (інший HTTP сервер) |

### Діспетчери
| DLL | Розмір | Роль |
|---|---|---|
| `EUSignRPC.dll` | 466 KB | JSON-RPC 2.0 dispatcher (~500 методів) |

### Крипто-ядро
| DLL | Розмір | Роль |
|---|---|---|
| `EUSignCP.dll` | 1.7 MB | Головна крипто-бібліотека (606 EU* функцій) |
| `CSPBase.dll` | 1.15 MB | Математика ДСТУ 4145/7564/7624/8845 |
| `CSPExtension.dll` | 80 KB | Статистичні тести |
| `PKIFormats.dll` | 975 KB | ASN.1 / X.509 парсер |

### PKCS#11 модулі
| DLL | Розмір | Роль |
|---|---|---|
| `PKCS11.EKeyAlmaz1C.dll` | 356 KB | Стандартний PKCS#11 для Алмаз |
| `PKCS11.Virtual.EKeyAlmaz1C.dll` | 1.0 MB | Софт-емуляція |
| `avcryptokinxt.dll` | 500 KB | PKCS#11 від "Автор" (SecureToken) |
| `efitkeynxt.dll` | 1.3 MB | PKCS#11 EFIT |

### Маршрутизатори і прямі драйвери
| DLL | Розмір | Роль |
|---|---|---|
| `KM.PKCS11.dll` | 283 KB | Роутер між PKCS#11 модулями |
| `KM.EKeyAlmaz1C.dll` | 676 KB | Прямий драйвер Алмаз (fallback) |
| `KM.EKeyAlmaz1CBTA.dll` | 245 KB | Bluetooth Алмаз варіант |

### UI
| DLL | Розмір | Роль |
|---|---|---|
| `EUSignCPAX.dll` | 131 KB | ActiveX для IE (legacy) |
| `CAGUI.dll` | 7 MB | GUI компоненти |

## Методика аналізу — 8 кроків

### Крок 1. Інвентаризація

```bash
# Всі DLL + метадані
for f in *.dll; do
    size=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f")
    arch=$(file -b "$f" | grep -oE "I386|x86_64")
    echo "$f  $size  $arch"
done | sort -k2 -n
```

Виявлено: всі 36 DLL — PE32 (32-bit I386), розмір від 80 KB до 7 MB.

### Крок 2. PDB (Program Database) шляхи

```bash
for f in *.dll; do
    pdb=$(strings "$f" | grep "\.pdb$" | head -1)
    [ -n "$pdb" ] && echo "$f -> $pdb"
done
```

PDB шляхи розкрили **структуру проекту IIT**:
```
D:\CertificateAuthority\Version13\Programms\EndUser\
    Libraries\
        NetworkCommunications\Host\Release\    → NCHostCP.pdb
        Sign\Release\                           → ...
D:\Hardware\KeyMedias\
    EKeyAlmaz1C\Release\PKCS11\                → PKCS11EKeyAlmaz1C.pdb
    EKeyAlmaz1C\Virtual\Release\               → Virtual.pdb
```

Це каталоги в **sandbox розробника IIT**. Дає уявлення про кодову базу.

### Крок 3. Експорти (головні функції)

```bash
objdump -p file.dll | awk '/Ordinal\/Name Pointer/,/PE File Base/' \
    | grep -E '^\s+\['
```

- `EUSignCP.dll` — 606 експортів з префіксом `EU*`
- `PKCS11.EKeyAlmaz1C.dll` — 68 експортів (стандарт PKCS#11 має 67)
- `CSPBase.dll` — 131 експорт (`DSTU4145*`, `DSTU7564*`, `DSTU7624*`, `DSTU8845*`)

### Крок 4. Імпорти (залежності)

```bash
objdump -p file.dll | grep "DLL Name"
```

Критичне відкриття:
- `PKCS11.EKeyAlmaz1C.dll` імпортує тільки `WinSCard`, `KERNEL32`, `ADVAPI32`
- Не імпортує `CSPBase.dll` статично → **динамічно завантажує через LoadLibraryW**

```bash
strings PKCS11.EKeyAlmaz1C.dll | grep -i "CSPBase\|GetProcAddress"
# → GetProcAddress
# → LoadLibraryW  
# → CSPBase.dll (UTF-16 encoded string)
```

### Крок 5. Constants та magic values

Шукаємо рядкові константи для розпізнавання:
- `CKM_` — PKCS#11 mechanism names
- `CKA_` — PKCS#11 attribute names  
- `EU_ERROR_` — IIT error codes
- `1.2.804.2.1.*` — українські OID

### Крок 6. Mechanism ID extraction (складний!)

Функція `C_GetMechanismList` — стандартна, повертає масив DWORD (mechanism IDs).

```python
# 1. Знайти export C_GetMechanismList в PE export table
# 2. Отримати RVA функції
# 3. Дізнайтесь де в код є CALL до іншої функції що повертає масив
# 4. В асемблері знайти "mov ecx, imm32" — imm32 є pointer на масив
# 5. Перейти до .data секції, прочитати DWORD array
# 6. Довжину масиву — з аргументу "mov edx, imm32" поряд

# У PKCS11.EKeyAlmaz1C.dll:
#   Function at file offset 0x13ae0 = C_GetMechanismList
#   Calls function at 0x21080 (copy function)
#   Which loads from offset 0x506bc (array of 12 DWORDs)
#   Result: [0x80420011, 0x80420012, ... 0x80420044]
```

Детальний приклад коду Python — в git історії комітів.

### Крок 7. Flag analysis для кожного mechanism

`C_GetMechanismInfo` повертає `CK_MECHANISM_INFO { ulMinKeySize, ulMaxKeySize, flags }`.

Декомпоновка функції показує **switch-case на основі mechanism ID**:

```python
# Опкоди x86 встановлюють поля структури:
#   c7 40 08 <imm32>  = mov [eax+8], imm32   → flags
#   c7 00 <imm32>     = mov [eax], imm32     → ulMinKeySize
#   c7 40 04 <imm32>  = mov [eax+4], imm32   → ulMaxKeySize
#   83 48 08 01       = or [eax+8], 1        → flags |= CKF_HW
```

Декодування дало таблицю flags для кожного з 12 mechanism IDs. **Але були
помилки** — див. Крок 8.

### Крок 8. Live validation (єдиний істинний шлях)

Статичний аналіз має ризик помилки. Наприклад, ми спочатку ідентифікували
`0x80420014` як DSTU 4145 через flags `SIGN | VERIFY`. Але:

- Розмір ключа 32 **байти** — занадто мало для EC DSTU 4145 (163-509 **біт**)
- Немає прапорців `EC_F_2M`, `EC_OID`
- Live тест показав: `0x80420014` це **MAC**, а не DSTU 4145
- Справжній DSTU 4145 — `0x80420031/32`

**Lesson learned:** статичний аналіз — **гіпотеза**. Live тест через
`pkcs11-tool --list-mechanisms` — **перевірка**.

Наш `opensc-test-almaz.ps1` автоматизує цю перевірку.

## Reproduce нашу роботу

Якщо є доступ до свіжої версії IIT (інсталятор з
<https://iit.com.ua/download/productfiles/> або архів DLL):

```bash
# 0. Інструменти (один раз)
apt-get install -y msitools cabextract p7zip-full innoextract
pip install .[analysis]           # pefile — лише для cross-check

# 1. Розпакувати, НЕ запускаючи (тип визначається за сигнатурою:
#    .msi → msiextract; Inno .exe → innoextract; CAB-SFX → cabextract; 7z/zip)
scripts/iit_unpack.sh EUInstall.msi downloads/iit/2026-09/euinstall

# 2. Інвентар + diff проти попередніх snapshot-ів + списки експортів
python scripts/iit_inventory.py downloads/iit/2026-09/euinstall --label euinstall \
    --snapshot-label S4-2026-09-euinstall --source "EUInstall.msi sha256=…" \
    --baseline docs/inventory/S3-2026-07-web_dll.json \
    --json docs/inventory/S4-2026-09-euinstall.json --md /tmp/S4.md \
    --exports-dir docs/inventory/exports

# 3. Реєстр версій по всіх snapshot-ах
python scripts/iit_inventory.py --registry docs/inventory/snapshot-*.json docs/inventory/S*.json \
    --md docs/DLL-REGISTRY.md

# 4. Ручний cross-check (те, що робив скрипт)
objdump -p PKCS11.EKeyAlmaz1C.dll | awk '/Ordinal\/Name Pointer/,/PE File Base/' | wc -l
objdump -p X.dll | grep -q C_GetFunctionList && echo "PKCS#11 module"
file -b X.dll | grep -oE "I386|x86_64"
sha256sum *.dll

# 5. Live тест mechanism IDs — ТІЛЬКИ на Windows з токеном (статика — гіпотеза)
pkcs11-tool --module PKCS11.EKeyAlmaz1C.dll --list-mechanisms
```

Що зберігаємо в git: лише похідні метадані (`docs/inventory/*.json`, списки
експортів, `docs/DLL-REGISTRY.md`). Самі DLL/інсталятори — в `.gitignore`.

## Етичні питання

Реверс-інжиніринг закритих бібліотек ІІТ — сіра зона:

- **За:** стандарти PKCS#11, JSON-RPC 2.0, DSTU — публічні. Ми використовуємо
  вже опубліковані DLL тільки для сумісності з нашим клієнтом.
- **Проти:** IIT може розглядати це як порушення EULA.

**Позиція проекту:** ми НЕ:
- Не розповсюджуємо DLL
- Не декомпілюємо бізнес-логіку
- Не копіюємо криптографічні алгоритми
- Не обходимо захист

Ми **тільки документуємо** публічні інтерфейси (експорти, JSON-RPC протокол),
щоб наш клієнт міг правильно їх викликати. Це **еквівалент написання header
файлу** для закритої бібліотеки.

Якщо IIT забажає співпраці — ми готові узгодити позицію.

## Подяки

- **Ilya Muromec** (muromec) — dstucrypt ecosystem, яка показала загальний
  вектор роботи з ДСТУ 4145
- **Ludovic Rousseau** — CCID driver з підтримкою Алмаз-1К
- **OpenSC project** — unifying tools для PKCS#11
