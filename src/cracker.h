#ifndef CRACKER_H
#define CRACKER_H

#include "handshake.h"
#include "crypto.h"

// Cracker configuration
struct cracker_config {
    char wordlist[256];         // Path to wordlist file
    char ssid[64];              // Target SSID
    int  max_passwords;         // Max passwords to try (0 = unlimited)
    int  show_tries;            // 1 = show each attempt, 0 = summary only
};

// Cracker statistics
struct cracker_stats {
    int total_tried;            // Total passwords tried
    int found;                  // 1 if password found
    char found_password[256];   // The found password (if any)
    double elapsed_seconds;     // Time elapsed
};

// Initialize cracker config with defaults
void cracker_config_init(struct cracker_config *config);

// Set wordlist path
void cracker_config_set_wordlist(struct cracker_config *config, const char *path);

// Set target SSID
void cracker_config_set_ssid(struct cracker_config *config, const char *ssid);

// Run dictionary attack
// Returns 0 if password found, 1 if not found, -1 on error
int cracker_attack(struct wpa_handshake *handshake,
                   struct cracker_config *config,
                   struct cracker_stats *stats);

// Print cracker statistics
void cracker_print_stats(struct cracker_stats *stats);

#endif // CRACKER_H
