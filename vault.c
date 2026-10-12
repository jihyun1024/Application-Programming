#include "vault.h"
#include "crypto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <conio.h>
#include <direct.h>
#include <windows.h>
#else
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#endif

#define VAULT_FILE "data/vault.dat"
#define VAULT_TEMP_FILE "data/vault.tmp"
#define OWNER_MAX 64
#define SERVICE_MAX 100
#define ENTRY_USERNAME_MAX 128
#define ENTRY_PASSWORD_MAX 256
#define ENTRY_LINE_MAX 640

typedef struct {
    unsigned long long id;
    char owner[OWNER_MAX];
    char service[SERVICE_MAX];
    char username[ENTRY_USERNAME_MAX];
    char password[ENTRY_PASSWORD_MAX];
    char password_hash[SHA256_HEX_SIZE];
} VaultEntry;

/* Reject fields that would break the simple pipe-delimited storage format. */
static int field_is_valid(const char *text)
{
    return text[0] != '\0' && strchr(text, '|') == NULL &&
           strchr(text, '\n') == NULL && strchr(text, '\r') == NULL;
}

/* Parse one record and reject malformed or oversized data. */
static int parse_entry(const char *line, VaultEntry *entry)
{
    return sscanf(line, "%llu|%63[^|]|%99[^|]|%127[^|]|%255[^|]|%64[^\r\n]",
                  &entry->id, entry->owner, entry->service, entry->username,
                  entry->password, entry->password_hash) == 6;
}

int vault_initialize(void)
{
#ifdef _WIN32
    if (_mkdir("data") != 0 && errno != EEXIST) {
        return 0;
    }
#else
    if (mkdir("data", 0700) != 0 && errno != EEXIST) {
        return 0;
    }
#endif
    FILE *file = fopen(VAULT_FILE, "a");
    if (file == NULL) {
        return 0;
    }
    return fclose(file) == 0;
}

int vault_read_line(const char *prompt, char *buffer, size_t buffer_size)
{
    if (buffer_size < 2) {
        return 0;
    }
    printf("%s", prompt);
    if (fgets(buffer, (int)buffer_size, stdin) == NULL) {
        return 0;
    }

    size_t length = strlen(buffer);
    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
        if (length > 1 && buffer[length - 2] == '\r') {
            buffer[length - 2] = '\0';
        }
        return 1;
    }
    if (!feof(stdin)) {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {
        }
        buffer[0] = '\0';
        return 0;
    }
    return 1;
}

int vault_read_password(const char *prompt, char *buffer, size_t buffer_size)
{
    size_t length = 0;

    if (buffer_size < 2) {
        return 0;
    }
    printf("%s", prompt);
    fflush(stdout);

#ifdef _WIN32
    for (;;) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            break;
        }
        if (ch == '\b') {
            if (length > 0) {
                --length;
                printf("\b \b");
            }
        } else if (ch >= 32 && ch <= 126 && length + 1 < buffer_size) {
            buffer[length++] = (char)ch;
            putchar('*');
        }
    }
#else
    struct termios original;
    int terminal_changed = tcgetattr(STDIN_FILENO, &original) == 0;
    if (terminal_changed) {
        struct termios hidden = original;
        hidden.c_lflag &= (tcflag_t)~ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden);
    }

    if (fgets(buffer, (int)buffer_size, stdin) == NULL) {
        if (terminal_changed) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        }
        return 0;
    }

    length = strlen(buffer);
    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[--length] = '\0';
    } else if (!feof(stdin)) {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {
        }
        if (terminal_changed) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        }
        buffer[0] = '\0';
        return 0;
    }

    if (terminal_changed) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
    }
#endif

    buffer[length] = '\0';
    putchar('\n');
    return 1;
}

void vault_clear_screen(void)
{
    int result;
#ifdef _WIN32
    result = system("cls");
#else
    result = system("clear");
#endif

    if (result != 0) {
        fputs("Unable to clear screen.\n", stderr);
    }
}

static unsigned long long next_entry_id(const char *owner)
{
    FILE *file = fopen(VAULT_FILE, "r");
    char line[ENTRY_LINE_MAX];
    VaultEntry entry;
    unsigned long long highest = 0;

    if (file == NULL) {
        return 1;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (parse_entry(line, &entry) && strcmp(entry.owner, owner) == 0 &&
            entry.id > highest) {
            highest = entry.id;
        }
    }

    fclose(file);
    return highest + 1;
}

int vault_add_entry(const char *owner)
{
    char service[SERVICE_MAX];
    char username[ENTRY_USERNAME_MAX];
    char password[ENTRY_PASSWORD_MAX];
    unsigned char digest[SHA256_SIZE];
    char password_hash[SHA256_HEX_SIZE];

    if (!vault_read_line("Service: ", service, sizeof(service)) ||
        !field_is_valid(service) ||
        !vault_read_line("Account username: ", username, sizeof(username)) ||
        !field_is_valid(username) ||
        !vault_read_password("Account password: ", password, sizeof(password)) ||
        !field_is_valid(password) ||
        !crypto_sha256(password, strlen(password), digest)) {
        fprintf(stderr, "Invalid input or unable to hash the password.\n");
        crypto_clear(password, sizeof(password));
        return 0;
    }

    crypto_to_hex(digest, sizeof(digest), password_hash);
    crypto_clear(digest, sizeof(digest));

    FILE *file = fopen(VAULT_FILE, "a");
    if (file == NULL) {
        crypto_clear(password, sizeof(password));
        return 0;
    }

    /* Plaintext is intentional for the assignment format, not safe at rest. */
    int success = fprintf(file, "%llu|%s|%s|%s|%s|%s\n",
                          next_entry_id(owner), owner, service, username,
                          password, password_hash) > 0;
    if (fclose(file) != 0) {
        success = 0;
    }

    crypto_clear(password, sizeof(password));
    crypto_clear(password_hash, sizeof(password_hash));
    return success;
}

void vault_list_entries(const char *owner)
{
    FILE *file = fopen(VAULT_FILE, "r");
    char line[ENTRY_LINE_MAX];
    VaultEntry entry;
    int found = 0;

    if (file == NULL) {
        puts("Unable to open vault.dat.");
        return;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (!parse_entry(line, &entry) || strcmp(entry.owner, owner) != 0) {
            continue;
        }
        found = 1;
        printf("\nENTRY %llu\nservice=%s\nusername=%s\npassword=%s\n"
               "hashedpw=%s\n", entry.id, entry.service, entry.username,
               entry.password, entry.password_hash);
    }

    if (!found) {
        puts("\nNo saved entries.");
    }
    fclose(file);
}

int vault_delete_entry(const char *owner, unsigned long long id)
{
    FILE *source = fopen(VAULT_FILE, "r");
    FILE *temporary;
    char line[ENTRY_LINE_MAX];
    VaultEntry entry;
    int removed = 0;
    int success = 1;

    if (source == NULL || (temporary = fopen(VAULT_TEMP_FILE, "w")) == NULL) {
        if (source != NULL) {
            fclose(source);
        }
        return 0;
    }

    while (fgets(line, sizeof(line), source) != NULL) {
        if (parse_entry(line, &entry) && entry.id == id &&
            strcmp(entry.owner, owner) == 0) {
            removed = 1;
        } else if (fputs(line, temporary) == EOF) {
            success = 0;
            break;
        }
    }
    if (ferror(source)) {
        success = 0;
    }
    if (fclose(source) != 0) {
        success = 0;
    }
    if (fclose(temporary) != 0) {
        success = 0;
    }
    if (!success || !removed) {
        remove(VAULT_TEMP_FILE);
        return 0;
    }

#ifdef _WIN32
    success = MoveFileExA(VAULT_TEMP_FILE, VAULT_FILE,
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    success = rename(VAULT_TEMP_FILE, VAULT_FILE) == 0;
#endif
    if (!success) {
        remove(VAULT_TEMP_FILE);
    }
    return success;
}

int vault_print_hmac(const char *master_password)
{
    FILE *file = fopen(VAULT_FILE, "rb");
    unsigned char *contents = NULL;
    unsigned char digest[SHA256_SIZE];
    long file_size;
    int success = 0;

    if (file == NULL || fseek(file, 0, SEEK_END) != 0 ||
        (file_size = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) {
        if (file != NULL) {
            fclose(file);
        }
        return 0;
    }

    contents = (unsigned char *)malloc((size_t)file_size + 1);

    /* The login password keys the displayed MAC; no expected MAC is stored for auto-checking. */
    if (contents != NULL &&
        fread(contents, 1, (size_t)file_size, file) == (size_t)file_size &&
        crypto_hmac_sha256(master_password, strlen(master_password), contents,
                           (size_t)file_size, digest)) {
        char hex[SHA256_HEX_SIZE];
        crypto_to_hex(digest, sizeof(digest), hex);
        printf("HMAC-SHA256(vault.dat): %s\n", hex);
        crypto_clear(hex, sizeof(hex));
        success = 1;
    }

    if (contents != NULL) {
        crypto_clear(contents, (size_t)file_size);
        free(contents);
    }
    crypto_clear(digest, sizeof(digest));
    fclose(file);
    return success;
}