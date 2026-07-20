#include "parser.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

// Radiotap present field bit positions
#define RADIOTAP_PRESENT_TSFT              0
#define RADIOTAP_PRESENT_FLAGS             1
#define RADIOTAP_PRESENT_RATE              2
#define RADIOTAP_PRESENT_CHANNEL           3
#define RADIOTAP_PRESENT_FHSS              4
#define RADIOTAP_PRESENT_DBM_ANTSIGNAL     5
#define RADIOTAP_PRESENT_DBM_ANTNOISE      6
#define RADIOTAP_PRESENT_LOCK_QUALITY      7
#define RADIOTAP_PRESENT_TX_ATTENUATION    8
#define RADIOTAP_PRESENT_DB_TX_ATTENUATION 9
#define RADIOTAP_PRESENT_DBM_TX_POWER     10
#define RADIOTAP_PRESENT_ANTENNA          11
#define RADIOTAP_PRESENT_DB_ANTSIGNAL     12
#define RADIOTAP_PRESENT_DB_ANTNOISE      13

// Channel frequencies for 802.11
static const int channel_frequencies[] = {
    0,      // channel 0 (invalid)
    2412,   // ch 1
    2417,   // ch 2
    2422,   // ch 3
    2427,   // ch 4
    2432,   // ch 5
    2437,   // ch 6
    2442,   // ch 7
    2447,   // ch 8
    2452,   // ch 9
    2457,   // ch 10
    2462,   // ch 11
    2467,   // ch 12
    2472,   // ch 13
    2484    // ch 14
};

// Convert frequency to channel number
static int freq_to_channel(int freq) {
    for (int i = 1; i <= 14; i++) {
        if (channel_frequencies[i] == freq) {
            return i;
        }
    }
    // Fallback calculation for non-standard frequencies
    if (freq >= 2412 && freq <= 2484) {
        return (freq - 2407) / 5;
    }
    return 0;
}

// Get size of each radiotap field based on bit position
static int radiotap_field_size(int bit) {
    switch (bit) {
        case RADIOTAP_PRESENT_TSFT:              return 8;  // uint64
        case RADIOTAP_PRESENT_FLAGS:             return 1;  // uint8
        case RADIOTAP_PRESENT_RATE:              return 1;  // uint8
        case RADIOTAP_PRESENT_CHANNEL:           return 4;  // uint16 + uint16 (freq + flags)
        case RADIOTAP_PRESENT_FHSS:              return 2;  // uint8 + uint8
        case RADIOTAP_PRESENT_DBM_ANTSIGNAL:     return 1;  // int8 (dBm)
        case RADIOTAP_PRESENT_DBM_ANTNOISE:      return 1;  // int8 (dBm)
        case RADIOTAP_PRESENT_LOCK_QUALITY:      return 2;  // uint16
        case RADIOTAP_PRESENT_TX_ATTENUATION:    return 2;  // uint16
        case RADIOTAP_PRESENT_DB_TX_ATTENUATION: return 2;  // uint16
        case RADIOTAP_PRESENT_DBM_TX_POWER:      return 1;  // int8
        case RADIOTAP_PRESENT_ANTENNA:           return 1;  // uint8
        case RADIOTAP_PRESENT_DB_ANTSIGNAL:      return 1;  // uint8
        case RADIOTAP_PRESENT_DB_ANTNOISE:       return 1;  // uint8
        default: return 0; // Unknown field
    }
}

// Pad to alignment boundary
static int align(int offset, int alignment) {
    return (offset + alignment - 1) & ~(alignment - 1);
}

void parser_init(void) {
}

// Extract SSID from Information Elements
int extract_ssid(const uint8_t *frame_body, int body_len, char *ssid_out, int ssid_max_len) {
    if (body_len < 12) return -1;

    int offset = 12; // Skip timestamp(8) + beacon interval(2) + capability(2)

    while (offset < body_len - 2) {
        uint8_t ie_id = frame_body[offset];
        uint8_t ie_len = frame_body[offset + 1];

        if (ie_id == 0 && ie_len > 0) {
            int copy_len = ie_len;
            if (copy_len >= ssid_max_len) {
                copy_len = ssid_max_len - 1;
            }
            memcpy(ssid_out, frame_body + offset + 2, copy_len);
            ssid_out[copy_len] = '\0';
            return copy_len;
        }

        offset += 2 + ie_len;
    }

    return -1;
}

// Extract channel from DS Parameter Set IE (ID = 3)
static int extract_channel_from_body(const uint8_t *body, int body_len) {
    if (body_len < 12) return 0;

    int offset = 12;

    while (offset < body_len - 2) {
        uint8_t ie_id = body[offset];
        uint8_t ie_len = body[offset + 1];

        // DS Parameter Set IE (ID = 3, length = 1)
        if (ie_id == 3 && ie_len == 1) {
            return body[offset + 2];
        }

        offset += 2 + ie_len;
    }

    return 0;
}

// Get frame type name
const char* get_frame_type_name(uint16_t type) {
    switch (type) {
        case WIFI_FRAME_TYPE_MANAGEMENT: return "Management";
        case WIFI_FRAME_TYPE_CONTROL:    return "Control";
        case WIFI_FRAME_TYPE_DATA:       return "Data";
        default:                         return "Unknown";
    }
}

// Get frame subtype name
const char* get_frame_subtype_name(uint16_t type, uint16_t subtype) {
    if (type == WIFI_FRAME_TYPE_MANAGEMENT) {
        switch (subtype) {
            case WIFI_SUBTYPE_BEACON:    return "Beacon";
            case WIFI_SUBTYPE_PROBE_REQ: return "Probe Request";
            case WIFI_SUBTYPE_PROBE_RESP:return "Probe Response";
            case WIFI_SUBTYPE_AUTH:      return "Authentication";
            case WIFI_SUBTYPE_DEAUTH:    return "Deauthentication";
            case WIFI_SUBTYPE_ASSOC_REQ: return "Association Request";
            case WIFI_SUBTYPE_ASSOC_RESP:return "Association Response";
            default:                     return "Management";
        }
    } else if (type == WIFI_FRAME_TYPE_DATA) {
        switch (subtype) {
            case WIFI_SUBTYPE_DATA:      return "Data";
            case WIFI_SUBTYPE_NULL:      return "Null";
            default:                     return "Data";
        }
    } else if (type == WIFI_FRAME_TYPE_CONTROL) {
        return "Control";
    }
    return "Unknown";
}

// Parse radiotap header - properly walk the bitmap
static int parse_radiotap(const uint8_t *packet, int length, struct parsed_packet *pkt) {
    if (length < 8) {
        return -1;
    }

    uint8_t version = packet[0];
    // uint8_t pad = packet[1];
    uint16_t rt_len = packet[2] | (packet[3] << 8);
    uint32_t present = packet[4] | (packet[5] << 8) | (packet[6] << 16) | (packet[7] << 24);

    if (version != 0 || rt_len > length) {
        return -1;
    }

    // Walk through present fields to find offsets
    int offset = 8; // Start after the fixed radiotap header (version + pad + length + present)
    int signal_offset = -1;
    int channel_offset = -1;

    for (int bit = 0; bit < 32; bit++) {
        if (present & (1 << bit)) {
            int field_size = radiotap_field_size(bit);
            if (field_size == 0) {
                // Unknown field - can't continue
                break;
            }

            if (bit == RADIOTAP_PRESENT_DBM_ANTSIGNAL) {
                signal_offset = offset;
            }
            if (bit == RADIOTAP_PRESENT_CHANNEL) {
                channel_offset = offset;
            }

            // Align to field's natural alignment
            if (bit == RADIOTAP_PRESENT_TSFT) {
                offset = align(offset, 8);
            } else if (bit == RADIOTAP_PRESENT_CHANNEL ||
                       bit == RADIOTAP_PRESENT_LOCK_QUALITY ||
                       bit == RADIOTAP_PRESENT_TX_ATTENUATION ||
                       bit == RADIOTAP_PRESENT_DB_TX_ATTENUATION) {
                offset = align(offset, 2);
            }

            offset += field_size;
        }
    }

    // Extract signal strength (dBm)
    if (signal_offset >= 0 && signal_offset < rt_len) {
        pkt->has_signal = 1;
        pkt->signal_dbm = (int8_t)packet[signal_offset];
    }

    // Extract channel from radiotap frequency
    if (channel_offset >= 0 && (channel_offset + 3) < rt_len) {
        uint16_t freq = packet[channel_offset] | (packet[channel_offset + 1] << 8);
        pkt->channel = freq_to_channel(freq);
    }

    return rt_len;
}

// Parse 802.11 MAC header
static int parse_mac_header(const uint8_t *frame, int length, struct parsed_packet *pkt) {
    if (length < 24) {
        return -1;
    }

    const struct wifi_mac_header *hdr = (const struct wifi_mac_header *)frame;

    pkt->frame_type = hdr->fc.type;
    pkt->frame_subtype = hdr->fc.subtype;
    pkt->is_protected = hdr->fc.protected_frame;

    int to_ds = hdr->fc.to_ds;
    int from_ds = hdr->fc.from_ds;

    if (!to_ds && !from_ds) {
        memcpy(pkt->dst_mac, hdr->addr1, 6);
        memcpy(pkt->src_mac, hdr->addr2, 6);
        memcpy(pkt->bssid, hdr->addr3, 6);
    } else if (to_ds && !from_ds) {
        memcpy(pkt->bssid, hdr->addr1, 6);
        memcpy(pkt->src_mac, hdr->addr2, 6);
        memcpy(pkt->dst_mac, hdr->addr3, 6);
    } else if (!to_ds && from_ds) {
        memcpy(pkt->dst_mac, hdr->addr1, 6);
        memcpy(pkt->bssid, hdr->addr2, 6);
        memcpy(pkt->src_mac, hdr->addr3, 6);
    } else {
        memcpy(pkt->dst_mac, hdr->addr1, 6);
        memcpy(pkt->src_mac, hdr->addr2, 6);
        memset(pkt->bssid, 0, 6);
    }

    return sizeof(struct wifi_mac_header);
}

// Parse beacon/probe response body
static void parse_beacon_body(const uint8_t *body, int body_len, struct parsed_packet *pkt) {
    if (body_len < 12) {
        return;
    }

    pkt->beacon_interval = ntohs(*(uint16_t *)(body + 8));
    pkt->capability = ntohs(*(uint16_t *)(body + 10));

    // Extract SSID
    pkt->ssid_len = extract_ssid(body, body_len, pkt->ssid, sizeof(pkt->ssid));
    if (pkt->ssid_len < 0) {
        pkt->ssid[0] = '\0';
        pkt->ssid_len = 0;
    }

    // Extract channel from DS Parameter Set IE (if not already set from radiotap)
    if (pkt->channel == 0) {
        pkt->channel = extract_channel_from_body(body, body_len);
    }
}

// Detect EAPOL frames
static void detect_eapol(const uint8_t *frame, int length, struct parsed_packet *pkt) {
    if (length >= 8) {
        if (frame[0] == 0xAA && frame[1] == 0xAA && frame[2] == 0x03 &&
            frame[3] == 0x00 && frame[4] == 0x00 && frame[5] == 0x00) {
            uint16_t ethertype = ntohs(*(uint16_t *)(frame + 6));
            if (ethertype == ETHERTYPE_EAPOL) {
                pkt->is_eapol = 1;
                pkt->eapol_type = 1;
            }
        }
    }
}

// Main parse function
struct parsed_packet parse_packet(const uint8_t *packet, int length) {
    struct parsed_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.raw_data = packet;
    pkt.raw_len = length;

    int rt_len = parse_radiotap(packet, length, &pkt);
    if (rt_len < 0) {
        return pkt;
    }

    const uint8_t *frame = packet + rt_len;
    int frame_len = length - rt_len;

    int mac_len = parse_mac_header(frame, frame_len, &pkt);
    if (mac_len < 0) {
        return pkt;
    }

    const uint8_t *body = frame + mac_len;
    int body_len = frame_len - mac_len;

    if (pkt.frame_type == WIFI_FRAME_TYPE_MANAGEMENT) {
        if (pkt.frame_subtype == WIFI_SUBTYPE_BEACON ||
            pkt.frame_subtype == WIFI_SUBTYPE_PROBE_RESP) {
            parse_beacon_body(body, body_len, &pkt);
        }
    } else if (pkt.frame_type == WIFI_FRAME_TYPE_DATA) {
        detect_eapol(body, body_len, &pkt);
    }

    pkt.valid = 1;
    return pkt;
}

// Print parsed packet info
void print_parsed_packet(const struct parsed_packet *pkt) {
    if (!pkt->valid) {
        return;
    }

    char src_str[18], dst_str[18], bssid_str[18];
    mac_to_str(pkt->src_mac, src_str);
    mac_to_str(pkt->dst_mac, dst_str);
    mac_to_str(pkt->bssid, bssid_str);

    printf("  Type: %s (%s)",
           get_frame_type_name(pkt->frame_type),
           get_frame_subtype_name(pkt->frame_type, pkt->frame_subtype));

    if (pkt->has_signal) {
        printf(" | Signal: %d dBm", pkt->signal_dbm);
    }

    printf("\n");
    printf("  Src: %s | Dst: %s | BSSID: %s\n", src_str, dst_str, bssid_str);

    if (pkt->frame_type == WIFI_FRAME_TYPE_MANAGEMENT) {
        if (pkt->frame_subtype == WIFI_SUBTYPE_BEACON ||
            pkt->frame_subtype == WIFI_SUBTYPE_PROBE_RESP) {
            printf("  SSID: %s | Channel: %d\n",
                   strlen(pkt->ssid) > 0 ? pkt->ssid : "(hidden)",
                   pkt->channel);
        }
    }

    if (pkt->is_eapol) {
        printf("  *** EAPOL DETECTED ***\n");
    }
}
