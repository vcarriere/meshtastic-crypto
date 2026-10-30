/*
 * Copyright (C) 2018 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "AES.h"
#include "Crypto.h"
#include <string.h>

// AES implementation for ESP32 using the hardware crypto module.

#if defined(CRYPTO_AES_ESP32)

AESCommon::AESCommon(uint8_t keySize) : configuredKeySize(keySize)
{
    esp_aes_init(&ctx);
}

AESCommon::~AESCommon()
{
    esp_aes_free(&ctx);
    clean(&ctx, sizeof(ctx));
}

size_t AESCommon::blockSize() const
{
    return 16;
}

size_t AESCommon::keySize() const
{
    return configuredKeySize;
}

bool AESCommon::setKey(const uint8_t *key, size_t len)
{
    if (!key || len != configuredKeySize)
        return false;
    return esp_aes_setkey(&ctx, key, len * 8) == 0;
}

void AESCommon::encryptBlock(uint8_t *output, const uint8_t *input)
{
    esp_aes_crypt_ecb(&ctx, ESP_AES_ENCRYPT, input, output);
}

void AESCommon::decryptBlock(uint8_t *output, const uint8_t *input)
{
#if defined(CRYPTO_AES_NO_DECRYPT)
    // Decryption compiled out; zero the output so callers never see stale data.
    (void)input;
    memset(output, 0, 16);
#else
    esp_aes_crypt_ecb(&ctx, ESP_AES_DECRYPT, input, output);
#endif
}

void AESCommon::clear()
{
    esp_aes_free(&ctx);
    clean(&ctx, sizeof(ctx));
    esp_aes_init(&ctx);
}

AES128::~AES128()
{
}

AES192::~AES192()
{
}

AES256::~AES256()
{
}

#endif // CRYPTO_AES_ESP32
