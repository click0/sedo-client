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
    if 'ekeyalmaz1c' in name and 'virtual' not in name:
        return CKM_IIT_DSTU4145         # 0x80420031
    if 'avcryptoki' in name or 'efitkey' in name:
        return CKM_DSTU4145              # 0x00000352
    return CKM_IIT_DSTU4145
