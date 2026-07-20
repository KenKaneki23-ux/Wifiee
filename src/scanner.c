#include "scanner.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
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
