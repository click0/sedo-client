# sedo-client Documentation

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.25
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

## Документи

### Огляд і архітектура

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — загальний огляд архітектури,
  data flow, розподіл відповідальностей Linux ↔ Windows
- **[MINIMUM-FILES-LIST.md](MINIMUM-FILES-LIST.md)** — точний перелік файлів
  для деплою (3 DLL + 9 cap = 4.1 MB)

### Реверс-інжиніринг

- **[IIT-ANALYSIS.md](IIT-ANALYSIS.md)** — повний звіт аналізу 36+ DLL ІІТ
  (EUSignAgent, EUSignRPC, EUSignCP, CSPBase, PKCS11 модулі)
- **[MECHANISM-IDS.md](MECHANISM-IDS.md)** — 12 PKCS#11 mechanism IDs з
  прапорцями, DSTU 4145 криві OIDs, таблиця співставлення з avcryptokinxt
- **[REVERSE-METHODOLOGY.md](REVERSE-METHODOLOGY.md)** — методологія
  аналізу, інструменти, reproduce steps, етичні міркування

### Протоколи

- **[PROTOCOL-JSON-RPC.md](PROTOCOL-JSON-RPC.md)** — повний опис IIT
  EUSignAgent JSON-RPC протоколу: endpoints, формат, послідовність
  авторизації, каталог ~500 методів, 110+ JSON полів сертифіката

## Швидкий індекс

**Хочу зрозуміти як це працює** → [ARCHITECTURE.md](ARCHITECTURE.md)

**Хочу дізнатись про реверс DLL** → [IIT-ANALYSIS.md](IIT-ANALYSIS.md)

**Треба точний mechanism ID для PKCS#11** → [MECHANISM-IDS.md](MECHANISM-IDS.md)

**Цікавий JSON-RPC протокол агента** → [PROTOCOL-JSON-RPC.md](PROTOCOL-JSON-RPC.md)

**Хочу повторити наш аналіз** → [REVERSE-METHODOLOGY.md](REVERSE-METHODOLOGY.md)

**Що ставити на Windows worker** → [../SETUP-WINDOWS.md](../SETUP-WINDOWS.md)

**OpenSC команди і troubleshooting** → [../OPENSC-QUICKSTART.md](../OPENSC-QUICKSTART.md)

**Fiddler capture для СЕДО auth** → [../FIDDLER-CAPTURE-GUIDE.md](../FIDDLER-CAPTURE-GUIDE.md)
