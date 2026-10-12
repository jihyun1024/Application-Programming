#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define SHA256_SIZE 32
#define SHA256_HEX_SIZE 65

/* Calculate a SHA-256 digest. Returns 1 on success and 0 on failure. */
int crypto_sha256(const void *data, size_t length,
                  unsigned char digest[SHA256_SIZE]);

/* Calculate HMAC-SHA256 using the supplied key and message. */
int crypto_hmac_sha256(const void *key, size_t key_length,
                       const void *data, size_t data_length,
                       unsigned char digest[SHA256_SIZE]);

/* Compare byte arrays without stopping at the first differing byte. */
int crypto_equal(const unsigned char *left, const unsigned char *right,
                 size_t length);

/* Clear sensitive data through a volatile pointer so it is not optimized out. */
void crypto_clear(void *data, size_t length);

/* Convert bytes to a lowercase hexadecimal string with a trailing NUL. */
void crypto_to_hex(const unsigned char *bytes, size_t length, char *hex);

#endif