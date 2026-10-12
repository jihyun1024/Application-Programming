#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>

/* Create data/ and an empty vault.dat when this is the first run. */
int vault_initialize(void);

/* Read one bounded line; return 1 on success and 0 on EOF or overflow. */
int vault_read_line(const char *prompt, char *buffer, size_t buffer_size);

/* Read a password without echoing its characters to the terminal. */
int vault_read_password(const char *prompt, char *buffer, size_t buffer_size);

/* Clear the console using the native command for the current platform. */
void vault_clear_screen(void);

/* Add, list, or remove entries belonging to owner in data/vault.dat. */
int vault_add_entry(const char *owner);
void vault_list_entries(const char *owner);
int vault_delete_entry(const char *owner, unsigned long long id);

/* Print HMAC-SHA256 of the complete vault file using the login password as key. */
int vault_print_hmac(const char *master_password);

#endif