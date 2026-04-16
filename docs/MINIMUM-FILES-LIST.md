# Мінімальний набір файлів для деплою

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.26
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

**Підтверджено через LIEF + static analysis.**

Для роботи PKCS11_EKeyAlmaz1C.dll на будь-якому комп'ютері потрібно:

## Обов'язкові DLL (3 шт, ~1.6 MB)

```
PKCS11_EKeyAlmaz1C.dll    356 KB   — entry point (C_GetFunctionList)
CSPBase.dll              1 185 KB   — DSTU/ГОСТ crypto (lazy-loaded)
CSPExtension.dll            80 KB   — статистичні тести (lazy-loaded)
                         ───────
                          ~1621 KB
```

## Параметри кривих (9 файлів, ~2.6 MB)

```
DSTU4145Parameters.cap      352 B   — OID mapping
DSTU4145CachePB.cap       1 725 KB   — Polynomial Basis точки
DSTU4145CacheNB.cap         784 KB   — Normal Basis точки
ECDHParameters.cap          352 B   — ECDH params
ECDSAParameters.cap         572 B   — ECDSA params (legacy)
GOST28147SBox.cap            80 B   — ГОСТ 28147 SBOX
GOST34311Parameters.cap      96 B   — ГОСТ 34.311 SBOX
PRNGParameters.cap           80 B   — PRNG init
RSAParameters.cap            40 B   — RSA (legacy)
                         ───────
                          ~2510 KB
```

## Структура директорії

```
C:\sedo-automation\libs\
├── PKCS11_EKeyAlmaz1C.dll
├── CSPBase.dll
├── CSPExtension.dll
├── DSTU4145Parameters.cap
├── DSTU4145CachePB.cap
├── DSTU4145CacheNB.cap
├── ECDHParameters.cap
├── ECDSAParameters.cap
├── GOST28147SBox.cap
├── GOST34311Parameters.cap
├── PRNGParameters.cap
└── RSAParameters.cap
```

**Всього: ~4.1 MB.** Всі файли мають бути в одній директорії.

## Системні залежності

- Windows 10/11 x64 (бібліотеки 32-bit, запускаються через WoW64)
- Smart Card service (`SCardSvr`) запущений
- Алмаз-1К USB підключений (розпізнається Windows)

## Не потрібно

Попри деякі старі гайди, **НЕ потрібні**:

- ❌ `KM.EKeyAlmaz1C.dll` — PKCS#11 модуль має власну USB комунікацію
- ❌ `KM.PKCS11.dll` — не використовується PKCS#11 напряму
- ❌ `EUSignAgent.dll` — це для JSON-RPC, не для PKCS#11
- ❌ `EUSignCP.dll` — високо-рівнева CAdES бібліотека
- ❌ `NCHostCP.dll` — CA Gateway
- ❌ IIT "Користувач ЦСК" GUI-програма — не потрібна якщо використовуємо PKCS#11

## Розгортання

### Мінімум (для чисто автоматизації):

```powershell
# Скопіювати з інсталяції IIT
$iitRoot = "C:\Program Files (x86)\Institute of Informational Technologies"
$target = "C:\sedo-automation\libs"
mkdir $target -Force

# Знайти і скопіювати всі 3 DLL + cap файли
Get-ChildItem $iitRoot -Recurse -Include "PKCS11_EKeyAlmaz1C.dll","CSPBase.dll","CSPExtension.dll","*.cap" |
    ForEach-Object { Copy-Item $_.FullName $target -Force }
```

### З пакету (якщо повного IIT немає):

Якщо тільки Web.zip пакет, `PKCS11_EKeyAlmaz1C.dll` буде відсутній.  
Завантажити повний IIT інсталятор з https://iit.com.ua.

## Перевірка

```powershell
# Базова перевірка — PKCS11 модуль завантажується
python -c "
import PyKCS11
lib = PyKCS11.PyKCS11Lib()
lib.load(r'C:\sedo-automation\libs\PKCS11_EKeyAlmaz1C.dll')
print('OK:', lib.getInfo().libraryDescription.strip())
"
```

Очікуваний вивід:
```
OK: E.key_Almaz-1C_Library
```

Якщо отримуєте `DLL was not found` — перевірте що CSPBase.dll поруч з PKCS11_EKeyAlmaz1C.dll.
