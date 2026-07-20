#ifndef SCANNER_H
#define SCANNER_H

#include "capture.h"
#include "parser.h"
#include "handshake.h"

// Maximum number of APs to track
#define MAX_APS 128

// AP information structure
struct ap_info {
    uint8_t bssid[6];
    char ssid[64];
    int channel;
    int8_t signal_dbm;
    int beacon_count;
    int last_seen;
};

// Scanner state structure
struct scanner_state {
    struct capture_handle *cap;
    struct wpa_handshake *handshake;
    struct ap_info aps[MAX_APS];
    int ap_count;
    int target_found;
    uint8_t target_bssid[6];
    int has_target;
    volatile int *running;  // Pointer to running flag
};

// Initialize scanner
void scanner_init(struct scanner_state *state, struct capture_handle *cap,
                  struct wpa_handshake *handshake, volatile int *running);

// Callback for packet capture
void scanner_packet_callback(const uint8_t *packet, int length, void *user_data);

// Add or update AP in list
int scanner_add_ap(struct scanner_state *state, const struct parsed_packet *pkt);

// Find AP by BSSID
struct ap_info* scanner_find_ap(struct scanner_state *state, const uint8_t *bssid);

// Print discovered APs
void scanner_print_aps(struct scanner_state *state);

// Start scanning (channel hop + capture)
int scanner_start(struct scanner_state *state, int dwell_time_ms);

// Start scanning for a fixed duration (seconds), returns AP count
int scanner_scan_duration(struct scanner_state *state, int dwell_time_ms, int duration_sec);

// Interactive network selection - prompts user to choose
// Returns index of selected AP, or -1 if cancelled
int scanner_select_target(struct scanner_state *state);

// Send deauthentication frames to force client reconnect
// count: number of deauth packets to send (0 = flood)
// Returns number of packets sent, -1 on error
int scanner_send_deauth(struct capture_handle *cap,
                        const uint8_t *target_bssid,
                        const uint8_t *client_mac,
                        int count);

// Get channel list (1-14)
void scanner_get_channels(int *channels, int *num_channels);

// Print debug stats
void scanner_print_debug_stats(void);

#endif // SCANNER_H
