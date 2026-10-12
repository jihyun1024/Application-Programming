#include "totp.h"
#include "crypto.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define TOTP_STEP_SECONDS 30
#define TOTP_SECRET_BYTES 20

static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/* Encode random bytes as unpadded RFC 4648 Base32 for authenticator apps. */
static void base32_encode(const unsigned char *input, size_t input_length,
                          char *output)
{
    unsigned int buffer = 0;
    int bits = 0;
    size_t output_length = 0;

    for (size_t i = 0; i < input_length; ++i) {
        buffer = (buffer << 8) | input[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output[output_length++] = base32_alphabet[(buffer >> bits) & 31];
        }
    }
    if (bits > 0) {
        output[output_length++] = base32_alphabet[(buffer << (5 - bits)) & 31];
    }
    output[output_length] = '\0';
}

/* Decode a Base32 secret into bytes; invalid characters cause failure. */
static int base32_decode(const char *input, unsigned char *output,
                         size_t output_size, size_t *output_length)
{
    unsigned int buffer = 0;
    int bits = 0;
    size_t count = 0;

    for (size_t i = 0; input[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)toupper((unsigned char)input[i]);
        int value;

        if (ch == '=' || ch == ' ' || ch == '-') {
            continue;
        }

        if (ch >= 'A' && ch <= 'Z') {
            value = ch - 'A';
        } else if (ch >= '2' && ch <= '7') {
            value = ch - '2' + 26;
        } else {
            return 0;
        }

        buffer = (buffer << 5) | (unsigned int)value;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (count == output_size) {
                return 0;
            }
            output[count++] = (unsigned char)(buffer >> bits);
        }
    }

    *output_length = count;
    return count > 0;
}

int totp_generate_secret(char secret[TOTP_SECRET_MAX])
{
    unsigned char random_bytes[TOTP_SECRET_BYTES];

    /* OpenSSL's cryptographic RNG avoids predictable rand()-based secrets. */
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        return 0;
    }

    base32_encode(random_bytes, sizeof(random_bytes), secret);
    crypto_clear(random_bytes, sizeof(random_bytes));
    return 1;
}

int totp_generate_code(const char *secret, unsigned long long time_step,
                       char code[TOTP_CODE_SIZE])
{
    unsigned char key[64];
    unsigned char counter[8];
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t key_length = 0;
    unsigned int digest_length = 0;

    if (!base32_decode(secret, key, sizeof(key), &key_length)) {
        return 0;
    }

    for (int i = 7; i >= 0; --i) {
        counter[i] = (unsigned char)(time_step & 0xff);
        time_step >>= 8;
    }

    if (HMAC(EVP_sha1(), key, (int)key_length, counter, sizeof(counter),
             digest, &digest_length) == NULL || digest_length < 20) {
        crypto_clear(key, sizeof(key));
        return 0;
    }

    /* RFC 6238 uses dynamic truncation of the HMAC-SHA1 result. */
    unsigned int offset = digest[digest_length - 1] & 0x0f;
    uint32_t binary = ((uint32_t)(digest[offset] & 0x7f) << 24) |
                      ((uint32_t)digest[offset + 1] << 16) |
                      ((uint32_t)digest[offset + 2] << 8) |
                      (uint32_t)digest[offset + 3];

    snprintf(code, TOTP_CODE_SIZE, "%06u", binary % 1000000U);

    crypto_clear(key, sizeof(key));
    crypto_clear(digest, sizeof(digest));
    return 1;
}

int totp_verify_code(const char *secret, const char *user_otp, int window)
{
    time_t now = time(NULL);

    if (now < 0 || user_otp == NULL || strlen(user_otp) != 6 || window < 0) {
        return 0;
    }

    for (size_t i = 0; i < 6; ++i) {
        if (!isdigit((unsigned char)user_otp[i])) {
            return 0;
        }
    }

    unsigned long long current_step = (unsigned long long)now / TOTP_STEP_SECONDS;

    for (int offset = -window; offset <= window; ++offset) {
        unsigned long long step = current_step;
        if (offset < 0) {
            if (step < (unsigned long long)(-offset)) {
                continue;
            }
            step -= (unsigned long long)(-offset);
        } else {
            step += (unsigned long long)offset;
        }

        char candidate_otp[TOTP_CODE_SIZE];
        if (totp_generate_code(secret, step, candidate_otp) &&
            strcmp(candidate_otp, user_otp) == 0) {
            return 1;
        }
    }
    return 0;
}

int totp_make_uri(const char *account, const char *secret,
                  char *uri, size_t uri_size)
{
    static const char hex[] = "0123456789ABCDEF";
    int written = snprintf(uri, uri_size, "otpauth://totp/PasswordManager:");

    if (written < 0 || (size_t)written >= uri_size) {
        return 0;
    }

    size_t used = (size_t)written;
    for (size_t i = 0; account[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)account[i];
        int unreserved = (ch >= 'A' && ch <= 'Z') ||
                         (ch >= 'a' && ch <= 'z') ||
                         (ch >= '0' && ch <= '9') ||
                         ch == '-' || ch == '.' || ch == '_' || ch == '~';
        size_t needed = unreserved ? 1 : 3;

        if (used + needed >= uri_size) {
            return 0;
        }

        if (unreserved) {
            uri[used++] = (char)ch;
        } else {
            uri[used++] = '%';
            uri[used++] = hex[ch >> 4];
            uri[used++] = hex[ch & 0x0f];
        }
    }

    written = snprintf(uri + used, uri_size - used,
                       "?secret=%s&issuer=PasswordManager&algorithm=SHA1"
                       "&digits=6&period=%d", secret, TOTP_STEP_SECONDS);
    return written >= 0 && (size_t)written < uri_size - used;
}