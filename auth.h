#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

#define AUTH_USERNAME_MAX 64
#define AUTH_HASH_SIZE 65
#define AUTH_SECRET_MAX 64

/* Return nonzero when at least one account is present in data/user.dat. */
int auth_user_exists(void);

/* Add an account containing the username, SHA-256 password hash, and TOTP secret. */
int auth_register(const char *username, const char *master_password,
                  const char *totp_secret);

/* Verify a username and master password; copy that user's TOTP secret on success. */
int auth_verify_master(const char *username, const char *master_password,
                       char *totp_secret, size_t secret_size);

#endif

