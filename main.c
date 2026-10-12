#include "auth.h"
#include "crypto.h"
#include "totp.h"
#include "vault.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MASTER_PASSWORD_MAX 256

/* Accept usernames that fit the record format and contain no field separator. */
static int username_is_valid(const char *username)
{
    return username[0] != '\0' && strlen(username) < AUTH_USERNAME_MAX &&
           strchr(username, '|') == NULL && strchr(username, '\n') == NULL;
}

/* Collect credentials, create the account, and display its authenticator URI. */
static int register_account(void)
{
    char username[AUTH_USERNAME_MAX];
    char password[MASTER_PASSWORD_MAX];
    char confirmation[MASTER_PASSWORD_MAX];
    char secret[TOTP_SECRET_MAX];
    char uri[TOTP_URI_MAX];

    if (!vault_read_line("New username: ", username, sizeof(username)) ||
        !username_is_valid(username) ||
        !vault_read_password("New master password: ", password, sizeof(password)) ||
        !vault_read_password("Confirm master password: ", confirmation,
                             sizeof(confirmation)) ||
        password[0] == '\0' || strcmp(password, confirmation) != 0) {
        printf("Invalid input or master passwords do not match.");
        crypto_clear(password, sizeof(password));
        crypto_clear(confirmation, sizeof(confirmation));
        return 0;
    }
    if (!totp_generate_secret(secret) ||
        !totp_make_uri(username, secret, uri, sizeof(uri)) ||
        !auth_register(username, password, secret)) {
        printf("Account registration failed.");
        crypto_clear(password, sizeof(password));
        crypto_clear(confirmation, sizeof(confirmation));
        crypto_clear(secret, sizeof(secret));
        return 0;
    }

    printf("\nAdd this account to Google Authenticator:");
    printf("Secret: %s\nURI: %s\n", secret, uri);
    printf("The secret is also stored in data/user.dat for this learning project.");
    crypto_clear(password, sizeof(password));
    crypto_clear(confirmation, sizeof(confirmation));
    crypto_clear(secret, sizeof(secret));
    return 1;
}

/* Authenticate with the master password and current TOTP before opening the vault. */
static int login_and_open_vault(void)
{
    char username[AUTH_USERNAME_MAX];
    char password[MASTER_PASSWORD_MAX];
    char secret[TOTP_SECRET_MAX];
    char code[32];

    if (!vault_read_line("Username: ", username, sizeof(username)) ||
        !vault_read_password("Master password: ", password, sizeof(password))) {
        return 0;
    }

    if (!auth_verify_master(username, password, secret, sizeof(secret))) {
        printf("\nInvalid username or master password.\n");
        crypto_clear(password, sizeof(password));
        return 0;
    }

    int totp_valid = vault_read_line("6-digit TOTP code: ", code, sizeof(code)) &&
                     totp_verify_code(secret, code, 1);
    crypto_clear(secret, sizeof(secret));

    if (!totp_valid) {
        printf("Invalid or expired TOTP code.");
        crypto_clear(password, sizeof(password));
        return 0;
    }

    vault_clear_screen();
    printf("\nAuthentication successful.\n");
    if (!vault_print_hmac(password)) {
        printf("Unable to calculate the vault HMAC.");
    }

    for (;;) {
        char choice[16];
        printf("\nPassword Manager\n1. Add entry\n2. List entries\n"
             "3. Delete entry\n4. Log out\n");
        if (!vault_read_line("Select: ", choice, sizeof(choice))) {
            continue;
        }

        if (strcmp(choice, "1") == 0) {
            if (vault_add_entry(username)) {
                printf("\nEntry saved.");
                vault_print_hmac(password);
            } else {
                printf("\nEntry was not saved.");
            }
        } else if (strcmp(choice, "2") == 0) {
            vault_list_entries(username);
        } else if (strcmp(choice, "3") == 0) {
            char id_text[32];
            char *end = NULL;
            unsigned long long id;

            if (!vault_read_line("Entry ID: ", id_text, sizeof(id_text))) {
                continue;
            }
            id = strtoull(id_text, &end, 10);
            if (end == id_text || *end != '\0' || id == 0 ||
                !vault_delete_entry(username, id)) {
                printf("\nEntry not found or could not be deleted.\n");
            } else {
                printf("\nEntry deleted.\n");
                vault_print_hmac(password);
            }
        } else if (strcmp(choice, "4") == 0) {
            break;
        } else {
            printf("Choose 1, 2, 3, or 4.\n");
        }
    }

    crypto_clear(password, sizeof(password));
    return 1;
}

int main(void)
{
    if (!vault_initialize()) {
        fprintf(stderr, "Unable to create or open the data directory.\n");
        return 1;
    }

    printf("CLI Two-Factor Password Manager");
    for (;;) {
        char choice[16];

        if (!auth_user_exists()) {
            printf("No account exists; register the first account.");
            if (register_account()) {
                continue;
            }
            continue;
        }

        printf("\n1. Login\n2. Register another user\n3. Exit\n");
        if (!vault_read_line("Select: ", choice, sizeof(choice))) {
            continue;
        }

        if (strcmp(choice, "1") == 0) {
            login_and_open_vault();
        } else if (strcmp(choice, "2") == 0) {
            register_account();
        } else if (strcmp(choice, "3") == 0) {
            break;
        } else {
            printf("Choose 1, 2, or 3.\n");
        }
    }
    return 0;
}