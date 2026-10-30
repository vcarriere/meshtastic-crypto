// SPDX-License-Identifier: MIT
#ifndef TEST_ESP_AES_H
#define TEST_ESP_AES_H

#include <stdint.h>

enum { AES128, AES192, AES256 };
enum { ESP_AES_ENCRYPT = 7, ESP_AES_DECRYPT = 9 };

// Deliberately larger and differently aligned than the historical 40-byte buffer.
typedef struct alignas(16) {
    uint64_t initialized;
    uint8_t padding[24];
    uint8_t key[32];
    unsigned int bits;
} esp_aes_context;

extern "C" {
void esp_aes_init(esp_aes_context *ctx);
void esp_aes_free(esp_aes_context *ctx);
int esp_aes_setkey(esp_aes_context *ctx, const unsigned char *key, unsigned int bits);
int esp_aes_crypt_ecb(esp_aes_context *ctx, int mode,
                      const unsigned char *input, unsigned char *output);
}
#endif
