#!/usr/bin/env bash
# iit_unpack.sh — розпакувати інсталятор IIT (.msi / Inno .exe / CAB-SFX /
# Delphi-обгортка з вбудованим MSI) у каталог, не запускаючи його.
#
#   scripts/iit_unpack.sh <installer> <outdir>
#
# Інструменти (Debian/Ubuntu): apt-get install msitools cabextract p7zip-full innoextract
# Далі: python scripts/iit_inventory.py <outdir> --label <name> ...
set -euo pipefail

usage() { echo "usage: $0 <installer.exe|.msi> <outdir>" >&2; exit 2; }
[[ $# -eq 2 ]] || usage
src=$1; out=$2
[[ -f "$src" ]] || { echo "no such file: $src" >&2; exit 2; }
mkdir -p "$out"

detect_type() {
    local f=$1 magic
    magic=$(head -c 8 "$f" | od -An -tx1 | tr -d ' \n')
    case "$magic" in
        d0cf11e0a1b11ae1) echo msi; return ;;
        377abcaf271c*)    echo 7z; return ;;
        504b0304*)        echo zip; return ;;
        4d5a*) ;;
        *) echo unknown; return ;;
    esac
    local inno
    inno=$(strings -n 8 "$f" | grep -m1 -oE "Inno Setup Setup Data \([0-9.]+\)" || true)
    if [[ -n "$inno" ]]; then echo "inno ${inno//[^0-9.]/}"; return; fi
    if grep -qa "Nullsoft" "$f"; then echo nsis; return; fi
    if grep -obUaP "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" "$f" >/dev/null 2>&1; then echo pe+msi; return; fi
    if grep -qa "MSCF" "$f"; then echo cab-sfx; return; fi
    echo pe
}

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1 (apt-get install $2)" >&2; return 1; }; }

unpack_msi() {
    if need msiextract msitools 2>/dev/null; then
        msiextract -C "$out" "$1"
    else
        need 7z p7zip-full
        7z x -y -o"$out/_streams" "$1" >/dev/null
        need cabextract cabextract
        for s in "$out"/_streams/*; do
            file -b "$s" | grep -q "Cabinet" && cabextract -q -d "$out" "$s"
        done
    fi
}

unpack_inno() {
    need innoextract innoextract
    if ! innoextract -d "$out" --collisions rename-all -e "$1"; then
        echo "innoextract failed — Inno version newer than supported? Use the .msi sibling" >&2
        echo "or build innoextract from https://github.com/dscharrer/innoextract" >&2
        exit 1
    fi
}

carve_msi() {
    local off
    off=$(grep -obUaP "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" "$1" | head -1 | cut -d: -f1)
    [[ -n "$off" ]] || { echo "no embedded MSI found" >&2; exit 1; }
    dd if="$1" of="$out/_embedded.msi" bs=1 skip="$off" status=none
    unpack_msi "$out/_embedded.msi"
}

type=$(detect_type "$src")
echo "type=$type file=$src"
case "$type" in
    msi)      unpack_msi "$src" ;;
    inno*)    unpack_inno "$src" ;;
    pe+msi)   carve_msi "$src" ;;
    cab-sfx)  need cabextract cabextract; cabextract -q -d "$out" "$src" ;;
    7z|zip)   need 7z p7zip-full; 7z x -y -o"$out" "$src" >/dev/null ;;
    nsis)     need 7z p7zip-full; 7z x -y -o"$out" "$src" >/dev/null ;;
    *)        echo "cannot unpack type=$type" >&2; exit 1 ;;
esac
n=$(find "$out" -type f | wc -l)
echo "type=$type files=$n outdir=$out"
