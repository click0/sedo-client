"""
PKCS#11 mechanism ID констант для української криптографії (ДСТУ 4145).

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.26
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
    "detect_dstu4145_mechanism",
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
# На HW токені 31 з 68 C_* функцій — stubs (повертають CKR_FUNCTION_NOT_SUPPORTED).
# Virtual токен реалізує все 68. Джерело: ADDENDUM v1, v2.
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


def detect_dstu4145_mechanism(pkcs11_module_path: str) -> int:
    """
    Визначити mechanism ID за ім'ям модуля.

    IIT (Алмаз, EKeyAlmaz1C) → 0x80420031
    ТОВ Автор (avcryptoki*)  → 0x00000352
    """
    name = pkcs11_module_path.lower()
    if 'ekeyalmaz1c' in name:
        return CKM_IIT_DSTU4145         # 0x80420031  (HW and Virtual share the same IDs)
    if 'avcryptoki' in name or 'efitkey' in name:
        return CKM_DSTU4145              # 0x00000352
    return CKM_IIT_DSTU4145
