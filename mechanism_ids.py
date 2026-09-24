"""
PKCS#11 mechanism ID констант для української криптографії (ДСТУ 4145).

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

# ═══════════════════════════════════════════════════════════════
# IIT vendor-defined mechanisms — ПІДТВЕРДЖЕНО на Алмаз-1К
# ═══════════════════════════════════════════════════════════════
#
# Формат id: 0x8042XXXX. Префікс 0x80420000 = CKM_VENDOR_DEFINED + IIT tag.
#
__all__ = [
    "IIT_MECHANISMS", "MECHANISM_SUPPORT", "CKM_IIT_DSTU4145",
    "CKM_IIT_DSTU4145_ALT", "CKM_DSTU4145", "is_supported",
    "detect_dstu4145_mechanism", "DSTU4145_SIGN_MECHANISMS",
    "pick_sign_mechanism", "choose_sign_mechanism", "detect_token_vendor",
    "NON_SIGNATURE_MECHANISMS",
]

# 32 bytes  = 256-bit symmetric key (Kalyna/Kupyna/ГОСТ)
# 163-509   = EC F_2M field sizes (DSTU 4145 curves GF(2^m))

IIT_MECHANISMS = {
    # Симетрична криптографія (32 bytes = 256-bit keys)
    0x80420011: "SYM_ENC_A",          # encrypt/decrypt (імовірно Kalyna variant)
    0x80420012: "SYM_ENC_B",          # encrypt/decrypt
    0x80420013: "SYM_ENC_C",          # encrypt/decrypt
    0x80420014: "SYM_MAC",            # sign/verify (HMAC/CMAC — НЕ DSTU 4145!)
    0x80420016: "SYM_WRAP",           # wrap/unwrap (DSTU 7624 key wrap)

    # Хеш
    0x80420021: "HASH_KUPYNA",        # digest (DSTU 7564 Kupyna)

    # ★★★ DSTU 4145 (ДСТУ 4145, EC над GF(2^m), key size 163-509 bit) ★★★
    0x80420031: "DSTU4145_SIGN_A",    # sign/verify EC F_2M — ГОЛОВНИЙ ПІДПИС
    0x80420032: "DSTU4145_SIGN_B",    # sign/verify EC F_2M — альтернативний

    # Генерація ключів
    0x80420041: "SYM_KEYGEN",                 # symmetric key-gen (32 bytes)
    0x80420042: "DSTU4145_KEYPAIR_GEN",       # EC key pair generation (163-509 bit)
    0x80420043: "DSTU4145_ECDH_A",            # derive (DSTU ECDH)
    0x80420044: "DSTU4145_ECDH_B",            # derive (DSTU ECDH variant)
}

# Поведінкова матриця: що реально працює на HW Алмаз vs Virtual токені.
# На HW токені близько 22 з 68 C_* функцій — stubs (CKR_FUNCTION_NOT_SUPPORTED):
# перелік — ADDENDUM v1 §2.2 (v2 каже «20+»; точне число — за кількістю
# експортів на спільну адресу stub-а, потребує бінарника).
# Virtual токен реалізує всі 68. Джерело: ADDENDUM v1, v2.
#
# Ключ — mechanism ID, значення — (hw_ok, virtual_ok).
# sedo-client використовує підпис (0x80420031/32), який працює скрізь.
MECHANISM_SUPPORT = {
    0x80420011: (False, True),   # SYM_ENC_A  — stub на HW
    0x80420012: (False, True),   # SYM_ENC_B  — stub на HW
    0x80420013: (False, True),   # SYM_ENC_C  — stub на HW
    0x80420014: (True,  True),   # SYM_MAC
    0x80420016: (True,  True),   # SYM_WRAP
    0x80420021: (True,  True),   # HASH_KUPYNA
    0x80420031: (True,  True),   # DSTU4145_SIGN_A  ← використовується sedo-client
    0x80420032: (True,  True),   # DSTU4145_SIGN_B
    0x80420041: (False, True),   # SYM_KEYGEN  — stub на HW
    0x80420042: (False, True),   # DSTU4145_KEYPAIR_GEN  — stub на HW
    0x80420043: (True,  True),   # DSTU4145_ECDH_A
    0x80420044: (True,  True),   # DSTU4145_ECDH_B
}


def is_supported(mechanism_id: int, token_type: str = "hw") -> bool:
    """
    Чи підтримує указаний тип токена цей mechanism.

    token_type: "hw" (Almaz-1K USB) або "virtual" (Key-6.dat).
    Невідомі mechanism IDs вважаються непідтриманими.
    """
    support = MECHANISM_SUPPORT.get(mechanism_id)
    if support is None:
        return False
    hw_ok, virtual_ok = support
    if token_type == "hw":
        return hw_ok
    if token_type == "virtual":
        return virtual_ok
    raise ValueError(f"Unknown token_type: {token_type!r}")

# ★ ГОЛОВНИЙ mechanism для підпису CMS/CAdES на Алмазі через IIT драйвер ★
CKM_IIT_DSTU4145 = 0x80420031

# Альтернатива якщо 31 не працює (обидва мають однакові flags)
CKM_IIT_DSTU4145_ALT = 0x80420032


# ═══════════════════════════════════════════════════════════════
# Standard PKCS#11 v3.0 IDs (використовує ТОВ "Автор" avcryptokinxt)
# ═══════════════════════════════════════════════════════════════

CKM_DSTU4145_KEY_PAIR_GEN  = 0x00000351
CKM_DSTU4145               = 0x00000352
CKM_DSTU4145_KEY_WRAP      = 0x00000353
CKM_DSTU4145_ECDH          = 0x00000354
CKM_DSTU7564               = 0x00000355
CKM_DSTU7564_HMAC_256      = 0x00000356
CKM_DSTU7564_HMAC_384      = 0x00000357
CKM_DSTU7564_HMAC_512      = 0x00000358


# ═══════════════════════════════════════════════════════════════
# Усі відомі DSTU 4145 sign mechanism IDs, у порядку пріоритету.
# Покриває IIT (Алмаз HW/Virtual) і Avest (CC-337 / ST-338, EfitKey).
# ═══════════════════════════════════════════════════════════════

DSTU4145_SIGN_MECHANISMS = (
    CKM_IIT_DSTU4145,        # 0x80420031  IIT Алмаз — головний
    CKM_IIT_DSTU4145_ALT,    # 0x80420032  IIT Алмаз — альтернатива
    CKM_DSTU4145,            # 0x00000352  стандарт PKCS#11 — Avest, ТОВ Автор
)


def detect_token_vendor(pkcs11_module_path: str) -> str:
    """
    Визначити вендора токена за ім'ям PKCS#11 модуля.

    Повертає одне з: "iit", "iit_virtual", "avest", "unknown".
    Ключ "avest" відповідає токенам SecureToken-337/338 та AvestKey/EfitKey —
    вендор ТОВ "Автор" (Avtor), у деяких джерелах Avest / AvestUA.
    """
    name = pkcs11_module_path.lower()
    if 'virtual' in name and 'ekeyalmaz1c' in name:
        return "iit_virtual"
    if 'ekeyalmaz1c' in name or 'ekeycrystal' in name:
        return "iit"
    if ('avcryptoki' in name or 'efitkey' in name
            or 'av337' in name or 'cc33' in name):
        return "avest"
    return "unknown"


def detect_dstu4145_mechanism(pkcs11_module_path: str) -> int:
    """
    Визначити mechanism ID за ім'ям модуля — лише як запасний варіант.

    Надійне джерело — список механізмів самого токена (choose_sign_mechanism;
    opensc-backend питає його через --list-mechanisms без PIN). Ця функція —
    для випадку, коли список недоступний.

    IIT (Алмаз, EKeyAlmaz1C)            → 0x80420031
    «Автор» Av337CryptokiD / CC-33x     → 0x80420031 — перевірено наживо на
        ST-338 (fw 1.3): модуль показує ІІТ-механізми 0x80420031/32 і НЕ має
        0x00000352. Раніше тут був 0x352, і opensc-backend на цьому токені
        отримав би CKR_MECHANISM_INVALID.
    «Автор» avcryptokinxt / EfitKey     → 0x00000352 (не перевірено наживо)
    Невідомий модуль                    → 0x80420031
    """
    name = pkcs11_module_path.lower()
    if detect_token_vendor(pkcs11_module_path) == "avest" \
            and not ("av337" in name or "cc33" in name):
        return CKM_DSTU4145              # 0x00000352
    return CKM_IIT_DSTU4145              # 0x80420031


def pick_sign_mechanism(available_ids) -> "int | None":
    """
    Вибрати найкращий DSTU 4145 sign mechanism зі списку доступних на токені.

    available_ids — iterable числових mechanism IDs (з C_GetMechanismList).
    Повертає перший збіг із DSTU4145_SIGN_MECHANISMS, або None якщо жодного
    відомого DSTU 4145 механізму немає (тоді викликач вирішує сам).
    """
    available = set(int(m) for m in available_ids)
    for mech in DSTU4145_SIGN_MECHANISMS:
        if mech in available:
            return mech
    return None


# Механізми, що мають CKF_SIGN, але НЕ є підписом ДСТУ 4145.
#
# 0x80420014 (SYM_MAC) — симетричний HMAC/CMAC. Підпис ним не є КЕП, СЕДО його
# відкине, а кожна спроба підписати спалює одну з 15 PIN-спроб Алмаз-1К. Саме
# цей ID помилково фігурував у OPENSC-QUICKSTART до v0.29. Tier 2/3 у
# choose_sign_mechanism мусить його обходити, інакше токен без 0x80420031/32
# отримав би MAC замість підпису.
#
# 0x80420015 — другий такий самий MAC (keySize 32/32, sign/verify), побачений
# на живому ST-338 «Автор» через Av337CryptokiD.dll; у таблиці ІІТ його немає.
NON_SIGNATURE_MECHANISMS = frozenset({
    0x80420014,
    0x80420015,
})


def choose_sign_mechanism(signing_ids) -> int:
    """
    Єдина політика вибору sign-механізму для обох PyKCS11 backend-ів
    (pkcs11_signer, virtual_signer). Приймає ID, що вже мають CKF_SIGN.

    1. Відомий DSTU 4145 ID (IIT 0x80420031/32 або стандарт 0x00000352).
    2. Перший vendor-defined (>= 0x80000000), крім NON_SIGNATURE_MECHANISMS.
    3. Перший зі списку, крім NON_SIGNATURE_MECHANISMS — останній fallback.

    Кидає ValueError, якщо список порожній або містить лише механізми, які
    свідомо не дають підпису ДСТУ 4145.
    """
    ids = [int(m) for m in signing_ids]
    if not ids:
        raise ValueError("no signing mechanisms available")
    known = pick_sign_mechanism(ids)
    if known is not None:
        return known
    candidates = [m for m in ids if m not in NON_SIGNATURE_MECHANISMS]
    if not candidates:
        raise ValueError(
            "only non-signature mechanisms available: "
            + ", ".join(f"0x{m:08X}" for m in ids))
    for mech in candidates:
        if mech >= 0x80000000:
            return mech
    return candidates[0]
