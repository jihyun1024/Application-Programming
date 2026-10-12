#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

int crypto_sha256(const void *data, size_t length,
                  unsigned char digest[SHA256_SIZE])
{
    unsigned int digest_length = 0;

    return EVP_Digest(data, length, digest, &digest_length,
                      EVP_sha256(), NULL) == 1 &&
           digest_length == SHA256_SIZE;
}

int crypto_hmac_sha256(const void *key, size_t key_length,
                       const void *data, size_t data_length,
                       unsigned char digest[SHA256_SIZE])
{
    unsigned int digest_length = 0;

    return HMAC(EVP_sha256(), key, (int)key_length, data, data_length,
                digest, &digest_length) != NULL &&
           digest_length == SHA256_SIZE;
}

int crypto_equal(const unsigned char *left, const unsigned char *right,
                 size_t length)
{
    unsigned char difference = 0;

    for (size_t i = 0; i < length; ++i) {
        difference |= (unsigned char)(left[i] ^ right[i]);
    }
    return difference == 0;
}

void crypto_clear(void *data, size_t length)
{
    volatile unsigned char *bytes = (volatile unsigned char *)data;

    while (length-- > 0) {
        *bytes++ = 0;
    }
}

void crypto_to_hex(const unsigned char *bytes, size_t length, char *hex)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < length; ++i) {
        hex[i * 2] = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    hex[length * 2] = '\0';
}