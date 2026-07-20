#include "handshake.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void handshake_init(struct wpa_handshake *hs) {
    memset(hs, 0, sizeof(*hs));
}

static int determine_message_type(const uint8_t *eapol_data, int eapol_len) {
    // EAPOL header: version(1) + type(1) + length(2) = 4 bytes
    // Key descriptor: type(1) + info(2) + key_length(2) + replay(8) + nonce(32) + iv(16) + rsc(8) + id(8) + mic(16) + data_len(2)
    // Total EAPOL Key header before key data: 95 bytes from start of EAPOL
    if (eapol_len < 99) {  // 4 (EAPOL header) + 95 (key header minimum)
        return -1;
    }

    // EAPOL type 3 = Key
    if (eapol_data[1] != 3) {
        return -1;
    }

    // Key info is at offset 5 (EAPOL header 4 bytes + descriptor type 1 byte)
    uint16_t key_info = (eapol_data[5] << 8) | eapol_data[6];

    int has_ack    = (key_info & 0x0080) != 0;
    int has_mic    = (key_info & 0x0100) != 0;
    int has_install= (key_info & 0x0040) != 0;
    int is_pairwise= (key_info & 0x0008) != 0;

    // Message 1: AP -> Client (ACK=1, MIC=0, Install=0, Pairwise=1)
    if (has_ack && !has_mic && is_pairwise) {
        return 1;
    }

    // Message 2: Client -> AP (ACK=0, MIC=1, Install=0, Pairwise=1, key_data_len > 0)
    if (!has_ack && has_mic && is_pairwise) {
        uint16_t key_data_len = (eapol_data[97] << 8) | eapol_data[98];
        if (key_data_len > 0) {
            return 2;
        } else {
            // Message 4: no key data
            return 4;
        }
    }

    // Message 3: AP -> Client (ACK=1, MIC=1, Install=1, Pairwise=1)
    if (has_ack && has_mic && has_install && is_pairwise) {
        return 3;
    }

    return -1;
}

int handshake_process_eapol(struct wpa_handshake *hs,
                            const uint8_t *src_mac,
                            const uint8_t *dst_mac,
                            const uint8_t *eapol_data,
                            int eapol_len) {
    if (eapol_len < 99) {
        return -1;
    }

    int msg_type = determine_message_type(eapol_data, eapol_len);
    if (msg_type < 0) {
        return -1;
    }

    // Determine AP MAC from first message or existing handshake
    if (msg_type == 1 && !hs->msg1_received) {
        // Message 1: source is AP
        memcpy(hs->ap_mac, src_mac, 6);
        memcpy(hs->client_mac, dst_mac, 6);
    }

    // Extract ANonce (offset 13 from EAPOL start: header 4 + desc_type 1 + info 2 + key_len 2 + replay 8 = 17, nonce at 17, 32 bytes)
    // Wait, let me recalculate:
    // EAPOL header: 4 bytes
    // Key descriptor type: 1 byte (offset 4)
    // Key info: 2 bytes (offset 5)
    // Key length: 2 bytes (offset 7)
    // Replay counter: 8 bytes (offset 9)
    // Nonce: 32 bytes (offset 17)
    // So nonce is at offset 17

    switch (msg_type) {
        case 1:
            memcpy(hs->anonce, eapol_data + 17, 32);
            hs->msg1_received = 1;
            log_info("  [+] Message 1 captured (ANonce)");
            break;

        case 2:
            memcpy(hs->snonce, eapol_data + 17, 32);
            memcpy(hs->mic, eapol_data + 81, 16);  // MIC at offset 4+1+2+2+8+32+16+8+8 = 81

            // Store full EAPOL for verification
            if (eapol_len <= MAX_EAPOL_SIZE) {
                memcpy(hs->eapol_frame, eapol_data, eapol_len);
                hs->eapol_len = eapol_len;
            }
            hs->msg2_received = 1;
            log_info("  [+] Message 2 captured (SNonce + MIC)");
            break;

        case 3:
            hs->msg3_received = 1;
            log_info("  [+] Message 3 captured");
            break;

        case 4:
            hs->msg4_received = 1;
            log_info("  [+] Message 4 captured (ACK)");
            break;
    }

    // Check if we have enough to crack (message 1 + message 2)
    if (hs->msg1_received && hs->msg2_received) {
        if (!hs->usable) {
            hs->usable = 1;
            log_success("Handshake USABLE for cracking! (got msg 1 + msg 2)");
        }
    }

    // Check if fully complete
    if (hs->msg1_received && hs->msg2_received &&
        hs->msg3_received && hs->msg4_received) {
        hs->complete = 1;
        log_success("Handshake COMPLETE (all 4 messages)");
    }

    return msg_type;
}

int handshake_is_usable(struct wpa_handshake *hs) {
    return hs->usable;
}

int handshake_is_complete(struct wpa_handshake *hs) {
    return hs->complete;
}

void handshake_print_status(struct wpa_handshake *hs) {
    char ap_str[18] = {0}, client_str[18] = {0};

    if (hs->msg1_received || hs->msg2_received || hs->msg3_received || hs->msg4_received) {
        mac_to_str(hs->ap_mac, ap_str);
        mac_to_str(hs->client_mac, client_str);
    }

    printf("\n=== Handshake Status ===\n");
    printf("AP MAC:     %s\n", (hs->msg1_received || hs->msg3_received) ? ap_str : "(not yet)");
    printf("Client MAC: %s\n", (hs->msg2_received || hs->msg4_received) ? client_str : "(not yet)");
    printf("SSID:       %s\n", strlen(hs->ssid) > 0 ? hs->ssid : "(not captured)");
    printf("Channel:    %d\n", hs->channel > 0 ? hs->channel : 0);

    printf("\nMessages:\n");
    printf("  Message 1: %s\n", hs->msg1_received ? "[CAPTURED]" : "[waiting]");
    printf("  Message 2: %s\n", hs->msg2_received ? "[CAPTURED]" : "[waiting]");
    printf("  Message 3: %s\n", hs->msg3_received ? "[CAPTURED]" : "[waiting]");
    printf("  Message 4: %s\n", hs->msg4_received ? "[CAPTURED]  " : "[waiting]");

    if (hs->complete) {
        printf("\nStatus: COMPLETE\n");
    } else if (hs->usable) {
        printf("\nStatus: USABLE FOR CRACKING\n");
    } else {
        printf("\nStatus: INCOMPLETE\n");
    }
    printf("========================\n\n");
}

int handshake_save(struct wpa_handshake *hs, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        log_error("Failed to open file for writing: %s", filename);
        return -1;
    }

    fprintf(fp, "WPA Handshake File\n");
    fprintf(fp, "AP MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            hs->ap_mac[0], hs->ap_mac[1], hs->ap_mac[2],
            hs->ap_mac[3], hs->ap_mac[4], hs->ap_mac[5]);
    fprintf(fp, "Client MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            hs->client_mac[0], hs->client_mac[1], hs->client_mac[2],
            hs->client_mac[3], hs->client_mac[4], hs->client_mac[5]);
    fprintf(fp, "SSID: %s\n", hs->ssid);
    fprintf(fp, "Channel: %d\n", hs->channel);
    fprintf(fp, "Usable: %d\n", hs->usable);
    fprintf(fp, "Complete: %d\n", hs->complete);

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
             hs->usable ? "USABLE" : "waiting");
}
