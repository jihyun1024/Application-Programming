#include "auth.h"
#include "crypto.h"

#include <stdio.h>
#include <string.h>

#define USER_FILE "data/user.dat"

/* Check whether the requested username already exists in the account file. */
static int auth_username_exists(const char *username)
{
    FILE *file = fopen(USER_FILE, "r");
    char line[AUTH_USERNAME_MAX + AUTH_HASH_SIZE + AUTH_SECRET_MAX + 4];
    char stored_name[AUTH_USERNAME_MAX];

    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "%63[^|]", stored_name) == 1 &&
            strcmp(stored_name, username) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}


int auth_user_exists(void)
{
    FILE *file = fopen(USER_FILE, "r");
    int exists;

    if (file == NULL) {
        return 0;
    }

    exists = fgetc(file) != EOF;
    fclose(file);
    return exists;
}


int auth_register(const char *username, const char *master_password,
    const char *totp_secret)
{
    unsigned char digest[SHA256_SIZE];
    char hash[SHA256_HEX_SIZE];

    FILE *file;

    if (username[0] == '\0' || strchr(username, '|') != NULL ||
        strchr(username, '\n') != NULL || strchr(username, '\r') != NULL ||
        master_password[0] == '\0' || totp_secret[0] == '\0' ||
        strchr(totp_secret, '|') != NULL || strchr(totp_secret, '\n') != NULL ||
        auth_username_exists(username) ||
        !crypto_sha256(master_password, strlen(master_password), digest)) {
        return 0;
    }

    crypto_to_hex(digest, sizeof(digest), hash);
    crypto_clear(digest, sizeof(digest));

    file = fopen(USER_FILE, "a");
    if (file == NULL) {
        return 0;
    }
    int success = fprintf(file, "%s|%s|%s\n", username, hash, totp_secret) > 0;

    if (fclose(file) != 0) {
        success = 0;
    }

    crypto_clear(hash, sizeof(hash));
    return success;
}


int auth_verify_master(const char *username, const char *master_password,
                       char *totp_secret, size_t secret_size)
{

    FILE *file = fopen(USER_FILE, "r");
    char line[AUTH_USERNAME_MAX + AUTH_HASH_SIZE + AUTH_SECRET_MAX + 4];
    char stored_name[AUTH_USERNAME_MAX];
    char stored_hash[AUTH_HASH_SIZE];
    char stored_secret[AUTH_SECRET_MAX];
    unsigned char digest[SHA256_SIZE];
    char actual_hash[SHA256_HEX_SIZE];
    int verified = 0;

    if (file == NULL ||
        !crypto_sha256(master_password, strlen(master_password), digest)) {
        if (file != NULL) {
            fclose(file);
        }
        return 0;
    }

    crypto_to_hex(digest, sizeof(digest), actual_hash);
    crypto_clear(digest, sizeof(digest));

    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "%63[^|]|%64[^|]|%63[^\r\n]", stored_name,
                   stored_hash, stored_secret) != 3) {
            continue;
        }

        if (strcmp(stored_name, username) == 0 &&
            strlen(stored_hash) == SHA256_SIZE * 2 &&
            strlen(stored_secret) < secret_size &&
            crypto_equal((const unsigned char *)actual_hash,
                         (const unsigned char *)stored_hash,
                         SHA256_SIZE * 2)) {
            strcpy(totp_secret, stored_secret);
            verified = 1;
            break;
        }
    }

    fclose(file);
    crypto_clear(actual_hash, sizeof(actual_hash));
    return verified;
}