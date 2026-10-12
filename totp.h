#ifndef TOTP_H
#define TOTP_H

#include <stddef.h>

#define TOTP_SECRET_MAX 64
#define TOTP_CODE_SIZE 7
#define TOTP_URI_MAX 512

/* Generate a random Base32 secret suitable for Google Authenticator. */
int totp_generate_secret(char secret[TOTP_SECRET_MAX]);

/* Generate the six-digit TOTP for a Unix-time step (normally 30 seconds). */
int totp_generate_code(const char *secret, unsigned long long time_step,
                       char code[TOTP_CODE_SIZE]);

/* Verify a six-digit code, allowing the requested number of adjacent steps. */
int totp_verify_code(const char *secret, const char *code, int window);

/* Build the otpauth URI that an authenticator application can enroll. */
int totp_make_uri(const char *account, const char *secret,
                  char *uri, size_t uri_size);

#endif

