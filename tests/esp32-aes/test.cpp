// SPDX-License-Identifier: MIT
#include "AES.h"
#include <openssl/evp.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <type_traits>
#include <vector>

static unsigned int initCalls, freeCalls, keyCalls, blockCalls;
static bool rejectKey, expectCleanInit;
static esp_aes_context *lastContext;
static const uint64_t initialized = 0x123456789abcdef0ULL;

static bool allZero(const void *data, size_t size)
{
    const unsigned char *bytes = static_cast<const unsigned char *>(data);
    for (size_t i = 0; i < size; ++i)
        if (bytes[i])
            return false;
    return true;
}

extern "C" void esp_aes_init(esp_aes_context *ctx)
{
    assert(reinterpret_cast<uintptr_t>(ctx) % alignof(esp_aes_context) == 0);
    if (expectCleanInit) {
        assert(allZero(ctx, sizeof(*ctx)));
        expectCleanInit = false;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->initialized = initialized;
    lastContext = ctx;
    ++initCalls;
}

extern "C" void esp_aes_free(esp_aes_context *ctx)
{
    assert(ctx->initialized == initialized);
    // The adapter must still perform its own non-optimizable wipe.
    memset(ctx, 0xa5, sizeof(*ctx));
    lastContext = ctx;
    ++freeCalls;
}

extern "C" int esp_aes_setkey(esp_aes_context *ctx, const unsigned char *key, unsigned int bits)
{
    assert(ctx->initialized == initialized);
    assert(bits == 128 || bits == 192 || bits == 256);
    ++keyCalls;
    if (rejectKey || bits == 192)
        return -1;
    memcpy(ctx->key, key, bits / 8);
    ctx->bits = bits;
    return 0;
}

extern "C" int esp_aes_crypt_ecb(esp_aes_context *ctx, int mode,
                                 const unsigned char *input, unsigned char *output)
{
    assert(ctx->initialized == initialized);
    assert(ctx->bits == 128 || ctx->bits == 256);
    assert(mode == ESP_AES_ENCRYPT || mode == ESP_AES_DECRYPT);
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    assert(cipher);
    const EVP_CIPHER *algorithm = ctx->bits == 128 ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
    assert(EVP_CipherInit_ex(cipher, algorithm, nullptr, ctx->key, nullptr, mode == ESP_AES_ENCRYPT));
    assert(EVP_CIPHER_CTX_set_padding(cipher, 0));
    int length = 0, finalLength = 0;
    assert(EVP_CipherUpdate(cipher, output, &length, input, 16));
    assert(length == 16);
    unsigned char finalBlock[16];
    assert(EVP_CipherFinal_ex(cipher, finalBlock, &finalLength));
    assert(finalLength == 0);
    EVP_CIPHER_CTX_free(cipher);
    ++blockCalls;
    return 0;
}

static std::vector<uint8_t> hex(const char *value)
{
    std::vector<uint8_t> bytes;
    while (*value) {
        unsigned int byte;
        assert(sscanf(value, "%2x", &byte) == 1);
        bytes.push_back(static_cast<uint8_t>(byte));
        value += 2;
    }
    return bytes;
}

template <typename Cipher>
static void vectorTest(const char *keyHex, const char *cipherHex)
{
    const auto key = hex(keyHex);
    const auto plain = hex("6bc1bee22e409f96e93d7e117393172a");
    const auto encrypted = hex(cipherHex);
    Cipher cipher;
    assert(cipher.blockSize() == 16);
    assert(cipher.keySize() == key.size());
    assert(cipher.setKey(key.data(), key.size()));
    uint8_t out[16];
    cipher.encryptBlock(out, plain.data());
    assert(memcmp(out, encrypted.data(), 16) == 0);
    cipher.encryptBlock(out, out);
    uint8_t expected[16];
    cipher.encryptBlock(expected, encrypted.data());
    assert(memcmp(out, expected, 16) == 0);

    const unsigned int calls = keyCalls;
    assert(!cipher.setKey(key.data(), key.size() - 1));
    assert(!cipher.setKey(nullptr, key.size()));
    assert(keyCalls == calls);
    cipher.encryptBlock(out, plain.data());
    assert(memcmp(out, encrypted.data(), 16) == 0);
    rejectKey = true;
    assert(!cipher.setKey(key.data(), key.size()));
    rejectKey = false;

    const unsigned int previousBlocks = blockCalls;
    cipher.decryptBlock(out, encrypted.data());
#if defined(CRYPTO_AES_NO_DECRYPT)
    assert(blockCalls == previousBlocks);
    assert(allZero(out, sizeof(out)));
#else
    assert(blockCalls == previousBlocks + 1);
    assert(memcmp(out, plain.data(), 16) == 0);
    memcpy(out, encrypted.data(), 16);
    cipher.decryptBlock(out, out);
    assert(memcmp(out, plain.data(), 16) == 0);
#endif

    expectCleanInit = true;
    cipher.clear();
    assert(!expectCleanInit);
    assert(cipher.keySize() == key.size());
    assert(lastContext->bits == 0);
    assert(allZero(lastContext->key, sizeof(lastContext->key)));
    assert(cipher.setKey(key.data(), key.size()));
    cipher.encryptBlock(out, plain.data());
    assert(memcmp(out, encrypted.data(), 16) == 0);

    static_assert(std::is_copy_assignable<Cipher>::value, "Preserve assignment compatibility");
    Cipher copy;
    copy = cipher;
    copy.encryptBlock(out, plain.data());
    assert(memcmp(out, encrypted.data(), 16) == 0);
}

int main()
{
    // NIST SP 800-38A, F.1.1 / F.1.5, first ECB block.
    vectorTest<AES128>("2b7e151628aed2a6abf7158809cf4f3c", "3ad77bb40d7a3660a89ecaf32466ef97");
    vectorTest<AES256>("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                       "f3eed1bdb5d2a03c064b5a7e3db181f8");
    {
        AES192 cipher;
        const uint8_t key[24] = {};
        assert(cipher.keySize() == 24);
        assert(!cipher.setKey(key, sizeof(key)));
        expectCleanInit = true;
        cipher.clear();
        assert(cipher.keySize() == 24);
    }
    alignas(AES128) unsigned char storage[sizeof(AES128)];
    AES128 *cipher = new (storage) AES128;
    const uint8_t key[16] = {};
    assert(cipher->setKey(key, sizeof(key)));
    const unsigned char *context = reinterpret_cast<unsigned char *>(lastContext);
    cipher->~AES128();
    assert(allZero(context, sizeof(esp_aes_context)));
    assert(initCalls == freeCalls);
    printf("PASS: SDK types/lifecycle, AES-128/256 vectors, in-place blocks, key errors, AES-192 rejection, clear/reuse, wipe, assignment\n");
}
