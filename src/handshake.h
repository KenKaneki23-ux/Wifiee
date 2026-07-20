#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>

// WPA Handshake message types
#define WPA_MSG_TYPE_1  1   // AP → Client (ANonce)
#define WPA_MSG_TYPE_2  2   // Client → AP (SNonce + MIC)
#define WPA_MSG_TYPE_3  3   // AP → Client (GTK + MIC)
#define WPA_MSG_TYPE_4  4   // Client → AP (ACK)

// Maximum EAPOL frame size
#define MAX_EAPOL_SIZE  256

// Handshake state
struct wpa_handshake {
    uint8_t ap_mac[6];          // AP MAC address
    uint8_t client_mac[6];      // Client MAC address
    uint8_t anonce[32];         // AP Nonce (from message 1)
    uint8_t snonce[32];         // Client Nonce (from message 2)
    uint8_t mic[16];            // Message integrity check
    uint8_t eapol_frame[MAX_EAPOL_SIZE];  // Full EAPOL frame for verification
    int eapol_len;              // Length of EAPOL frame

    // State tracking
    int msg1_received;          // 1 if message 1 received
    int msg2_received;          // 1 if message 2 received
    int msg3_received;          // 1 if message 3 received
    int msg4_received;          // 1 if message 4 received
    int complete;               // 1 if handshake complete (all 4 messages)

    // AP info (from beacons)
    char ssid[64];              // Network name
    int channel;                // AP channel
};

// Initialize handshake structure
void handshake_init(struct wpa_handshake *hs);

// Process EAPOL frame
// Returns message type (1-4) or -1 if not part of handshake
int handshake_process_eapol(struct wpa_handshake *hs,
                            const uint8_t *src_mac,
                            const uint8_t *dst_mac,
                            const uint8_t *eapol_data,
                            int eapol_len);

// Check if handshake is complete
int handshake_is_complete(struct wpa_handshake *hs);

// Print handshake status
void handshake_print_status(struct wpa_handshake *hs);

// Save handshake to file (for use with aircrack-ng or other tools)
// Returns 0 on success, -1 on failure
int handshake_save(struct wpa_handshake *hs, const char *filename);

// Get handshake info string
void handshake_get_info(struct wpa_handshake *hs, char *buffer, int bufsize);

#endif // HANDSHAKE_H
