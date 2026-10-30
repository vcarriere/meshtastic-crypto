#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT HUP INT TERM
for layout in modern legacy; do
    for decrypt in enabled disabled; do
        flags=""
        if [ "$decrypt" = disabled ]; then
            flags="-DCRYPTO_AES_NO_DECRYPT=1"
        fi
        "${CXX:-g++}" -std=c++11 -O2 -flto -Wall -Wextra -Werror -Werror=lto-type-mismatch \
            -DESP32=1 $flags -I"$root/tests/esp32-aes/$layout" -I"$root" \
            "$root/tests/esp32-aes/test.cpp" "$root/AESEsp32.cpp" \
            "$root/BlockCipher.cpp" "$root/Crypto.cpp" -lcrypto -o "$build/test"
        printf '%s header, decryption %s: ' "$layout" "$decrypt"
        "$build/test"
    done
done
