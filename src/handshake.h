#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>

#define WPA_MSG_TYPE_1  1
#define WPA_MSG_TYPE_2  2
#define WPA_MSG_TYPE_3  3
#define WPA_MSG_TYPE_4  4

#define MAX_EAPOL_SIZE  256

struct wpa_handshake {
    uint8_t ap_mac[6];
    uint8_t client_mac[6];
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t mic[16];
    uint8_t eapol_frame[MAX_EAPOL_SIZE];
    int eapol_len;

    int msg1_received;
    int msg2_received;
    int msg3_received;
    int msg4_received;
    int usable;      // We have enough to crack (msg1 + msg2)
    int complete;    // All 4 messages received

    char ssid[64];
    int channel;
};

void handshake_init(struct wpa_handshake *hs);
int handshake_process_eapol(struct wpa_handshake *hs,
                            const uint8_t *src_mac,
                            const uint8_t *dst_mac,
                            const uint8_t *eapol_data,
                            int eapol_len);
int handshake_is_usable(struct wpa_handshake *hs);
int handshake_is_complete(struct wpa_handshake *hs);
void handshake_print_status(struct wpa_handshake *hs);
int handshake_save(struct wpa_handshake *hs, const char *filename);
void handshake_get_info(struct wpa_handshake *hs, char *buffer, int bufsize);

#endif // HANDSHAKE_H
