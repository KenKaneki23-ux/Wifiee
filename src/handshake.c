#include "handshake.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

// EAPOL Key descriptor type
#define EAPOL_KEY_DESCRIPTOR_TYPE_WPA  2
#define EAPOL_KEY_DESCRIPTOR_TYPE_RSN  2

// EAPOL Key Info flags
#define WPA_KEY_INFO_TYPE_MASK    0x0007
#define WPA_KEY_INFO_TYPE_HMAC    0x0001
#define WPA_KEY_INFO_TYPE_CCMP    0x0002
#define WPA_KEY_INFO_TYPE_TKIP    0x0003

#define WPA_KEY_INFO_KEY_TYPE     0x0008  // 1 = Pairwise, 0 = Group
#define WPA_KEY_INFO_MIC          0x0100  // MIC present
#define WPA_KEY_INFO_SECURE       0x0200
#define WPA_KEY_INFO_REQUEST      0x0800
#define WPA_KEY_INFO_ACK          0x0080  // ACK bit
#define WPA_KEY_INFO_INSTALL      0x0040  // Install bit

// EAPOL structure (simplified)
struct eapol_header {
    uint8_t  version;
    uint8_t  type;          // 3 = Key
    uint16_t length;
} __attribute__((packed));

// EAPOL Key structure (WPA/RSN)
struct eapol_key {
    uint8_t  descriptor_type;    // 254 for WPA, 2 for RSN
    uint16_t info;               // Key info
    uint16_t key_length;
    uint64_t replay_counter;
    uint8_t  nonce[32];          // ANonce or SNonce
    uint8_t  iv[16];
    uint8_t  key_rsc[8];
    uint8_t  key_id[8];
    uint8_t  mic[16];           // Message Integrity Check
    uint16_t key_data_length;
    // Followed by key data (encrypted)
} __attribute__((packed));

void handshake_init(struct wpa_handshake *hs) {
    memset(hs, 0, sizeof(*hs));
}

// Determine message type based on key info flags
static int determine_message_type(const struct eapol_key *key) {
    uint16_t info = ntohs(key->info);
    int has_ack = (info & WPA_KEY_INFO_ACK) != 0;
    int has_mic = (info & WPA_KEY_INFO_MIC) != 0;
    int has_install = (info & WPA_KEY_INFO_INSTALL) != 0;
    int is_pairwise = (info & WPA_KEY_INFO_KEY_TYPE) != 0;

    // Message 1: AP → Client (ACK=1, MIC=0, Install=0)
    if (has_ack && !has_mic && !has_install && is_pairwise) {
        return WPA_MSG_TYPE_1;
    }

    // Message 2: Client → AP (ACK=0, MIC=1, Install=0)
    if (!has_ack && has_mic && !has_install && is_pairwise) {
        return WPA_MSG_TYPE_2;
    }

    // Message 3: AP → Client (ACK=1, MIC=1, Install=1)
    if (has_ack && has_mic && has_install && is_pairwise) {
        return WPA_MSG_TYPE_3;
    }

    // Message 4: Client → AP (ACK=0, MIC=1, Install=0)
    // Same as message 2, but we track separately
    if (!has_ack && has_mic && !has_install && is_pairwise) {
        return WPA_MSG_TYPE_4;
    }

    return -1; // Unknown
}

// Determine direction (AP to Client or Client to AP)
static int is_ap_to_client(const uint8_t *src_mac, const uint8_t *dst_mac,
                           const uint8_t *ap_mac) {
    return memcmp(src_mac, ap_mac, 6) == 0;
}

int handshake_process_eapol(struct wpa_handshake *hs,
                            const uint8_t *src_mac,
                            const uint8_t *dst_mac,
                            const uint8_t *eapol_data,
                            int eapol_len) {
    if (eapol_len < sizeof(struct eapol_header) + sizeof(struct eapol_key)) {
        return -1;
    }

    const struct eapol_header *eapol = (const struct eapol_header *)eapol_data;

    // Check if this is a Key frame (type 3)
    if (eapol->type != 3) {
        return -1;
    }

    const struct eapol_key *key = (const struct eapol_key *)(eapol_data + sizeof(struct eapol_header));

    // Determine message type
    int msg_type = determine_message_type(key);
    if (msg_type < 0) {
        return -1;
    }

    // Determine AP MAC (from first message or from existing handshake)
    uint8_t ap_mac[6];
    if (hs->msg1_received) {
        memcpy(ap_mac, hs->ap_mac, 6);
    } else if (msg_type == WPA_MSG_TYPE_1) {
        // First message: source is AP
        memcpy(ap_mac, src_mac, 6);
        memcpy(hs->ap_mac, src_mac, 6);
        memcpy(hs->client_mac, dst_mac, 6);
    } else {
        // Not first message and no AP MAC known
        return -1;
    }

    // Process based on message type
    switch (msg_type) {
        case WPA_MSG_TYPE_1:
            // AP → Client: Extract ANonce
            if (!is_ap_to_client(src_mac, dst_mac, ap_mac)) {
                return -1; // Not from AP
            }
            memcpy(hs->anonce, key->nonce, 32);
            hs->msg1_received = 1;
            log_info("Received Message 1 (ANonce)");
            break;

        case WPA_MSG_TYPE_2:
            // Client → AP: Extract SNonce and MIC
            if (is_ap_to_client(src_mac, dst_mac, ap_mac)) {
                return -1; // Should be from client
            }
            memcpy(hs->snonce, key->nonce, 32);
            memcpy(hs->mic, key->mic, 16);
            // Store EAPOL frame for verification
            if (eapol_len <= MAX_EAPOL_SIZE) {
                memcpy(hs->eapol_frame, eapol_data, eapol_len);
                hs->eapol_len = eapol_len;
            }
            hs->msg2_received = 1;
            log_info("Received Message 2 (SNonce + MIC)");
            break;

        case WPA_MSG_TYPE_3:
            // AP → Client: Verify with ANonce
            if (!is_ap_to_client(src_mac, dst_mac, ap_mac)) {
                return -1; // Not from AP
            }
            hs->msg3_received = 1;
            log_info("Received Message 3");
            break;

        case WPA_MSG_TYPE_4:
            // Client → AP: Final ACK
            if (is_ap_to_client(src_mac, dst_mac, ap_mac)) {
                return -1; // Should be from client
            }
            hs->msg4_received = 1;
            log_info("Received Message 4 (ACK)");
            break;
    }

    // Check if handshake is now complete
    if (hs->msg1_received && hs->msg2_received &&
        hs->msg3_received && hs->msg4_received) {
        hs->complete = 1;
        log_success("Handshake COMPLETE!");
    }

    return msg_type;
}

int handshake_is_complete(struct wpa_handshake *hs) {
    return hs->complete;
}

void handshake_print_status(struct wpa_handshake *hs) {
    char ap_str[18], client_str[18];
    mac_to_str(hs->ap_mac, ap_str);
    mac_to_str(hs->client_mac, client_str);

    printf("\n=== Handshake Status ===\n");
    printf("AP MAC:     %s\n", hs->msg1_received ? ap_str : "(not yet)");
    printf("Client MAC: %s\n", hs->msg2_received ? client_str : "(not yet)");
    printf("SSID:       %s\n", strlen(hs->ssid) > 0 ? hs->ssid : "(not captured)");
    printf("Channel:    %d\n", hs->channel > 0 ? hs->channel : 0);

    printf("\nMessages:\n");
    printf("  Message 1: %s\n", hs->msg1_received ? "[RECEIVED]" : "[waiting]");
    printf("  Message 2: %s\n", hs->msg2_received ? "[RECEIVED]" : "[waiting]");
    printf("  Message 3: %s\n", hs->msg3_received ? "[RECEIVED]" : "[waiting]");
    printf("  Message 4: %s\n", hs->msg4_received ? "[RECEIVED]" : "[waiting]");

    printf("\nStatus: %s\n", hs->complete ? "COMPLETE" : "INCOMPLETE");
    printf("========================\n\n");
}

int handshake_save(struct wpa_handshake *hs, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        log_error("Failed to open file for writing: %s", filename);
        return -1;
    }

    // Write header
    fprintf(fp, "WPA Handshake File\n");
    fprintf(fp, "AP MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            hs->ap_mac[0], hs->ap_mac[1], hs->ap_mac[2],
            hs->ap_mac[3], hs->ap_mac[4], hs->ap_mac[5]);
    fprintf(fp, "Client MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            hs->client_mac[0], hs->client_mac[1], hs->client_mac[2],
            hs->client_mac[3], hs->client_mac[4], hs->client_mac[5]);
    fprintf(fp, "SSID: %s\n", hs->ssid);
    fprintf(fp, "Channel: %d\n", hs->channel);
    fprintf(fp, "Complete: %d\n", hs->complete);

    // Write EAPOL frame in hex
    fprintf(fp, "\nEAPOL Frame (hex):\n");
    for (int i = 0; i < hs->eapol_len; i++) {
        fprintf(fp, "%02X", hs->eapol_frame[i]);
        if ((i + 1) % 32 == 0) {
            fprintf(fp, "\n");
        }
    }
    fprintf(fp, "\n");

    fclose(fp);
    log_success("Handshake saved to %s", filename);
    return 0;
}

void handshake_get_info(struct wpa_handshake *hs, char *buffer, int bufsize) {
    char ap_str[18] = {0}, client_str[18] = {0};

    if (hs->msg1_received) {
        mac_to_str(hs->ap_mac, ap_str);
    } else {
        strncpy(ap_str, "waiting", sizeof(ap_str));
    }

    if (hs->msg2_received) {
        mac_to_str(hs->client_mac, client_str);
    } else {
        strncpy(client_str, "waiting", sizeof(client_str));
    }

    snprintf(buffer, bufsize,
             "AP: %s | Client: %s | SSID: %s | Msgs: %d%d%d%d | %s",
             ap_str, client_str,
             strlen(hs->ssid) > 0 ? hs->ssid : "?",
             hs->msg1_received, hs->msg2_received,
             hs->msg3_received, hs->msg4_received,
             hs->complete ? "COMPLETE" : "waiting");
}
