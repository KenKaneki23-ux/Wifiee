#include "parser.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

// Global parser state (reserved for future use)
void parser_init(void) {
    // Initialize any global state if needed
}

// Extract SSID from Information Elements
int extract_ssid(const uint8_t *frame_body, int body_len, char *ssid_out, int ssid_max_len) {
    int offset = 0;

    // Skip fixed fields (timestamp 8 bytes + beacon interval 2 bytes + capability 2 bytes)
    // For beacon: 12 bytes, for probe response: 12 bytes
    // We'll handle both by checking the frame body

    // Skip fixed parameters (assume beacon/probe response format)
    if (body_len < 12) {
        return -1;
    }
    offset = 12; // Skip timestamp(8) + beacon interval(2) + capability(2)

    // Parse Information Elements
    while (offset < body_len - 2) {
        uint8_t ie_id = frame_body[offset];
        uint8_t ie_len = frame_body[offset + 1];

        // SSID IE (ID = 0)
        if (ie_id == 0 && ie_len > 0) {
            int copy_len = ie_len;
            if (copy_len >= ssid_max_len) {
                copy_len = ssid_max_len - 1;
            }
            memcpy(ssid_out, frame_body + offset + 2, copy_len);
            ssid_out[copy_len] = '\0';
            return copy_len;
        }

        offset += 2 + ie_len; // Move to next IE
    }

    return -1; // SSID not found
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

// Parse radiotap header
static int parse_radiotap(const uint8_t *packet, int length, struct parsed_packet *pkt) {
    if (length < sizeof(struct radiotap_header)) {
        return -1;
    }

    const struct radiotap_header *rt = (const struct radiotap_header *)packet;

    // Check version
    if (rt->version != 0) {
        return -1;
    }

    int rt_len = rt->length;
    if (rt_len > length) {
        return -1;
    }

    // Try to extract signal strength if present
    // Radiotap fields are bitmap-based, simplified extraction
    if (rt->present & (1 << 18)) { // Bit 18: SS (signal strength in dBm)
        // Signal strength is at a variable offset, simplified here
        pkt->has_signal = 1;
        // Note: Actual offset calculation requires walking all present flags
        // For now, we'll set a default
        pkt->signal_dbm = -50; // Placeholder
    }

    return rt_len;
}

// Parse 802.11 MAC header
static int parse_mac_header(const uint8_t *frame, int length, struct parsed_packet *pkt) {
    if (length < sizeof(struct wifi_mac_header)) {
        return -1;
    }

    const struct wifi_mac_header *hdr = (const struct wifi_mac_header *)frame;

    // Extract frame control fields
    pkt->frame_type = hdr->fc.type;
    pkt->frame_subtype = hdr->fc.subtype;
    pkt->is_protected = hdr->fc.protected_frame;

    // Extract addresses based on To DS / From DS flags
    int to_ds = hdr->fc.to_ds;
    int from_ds = hdr->fc.from_ds;

    if (!to_ds && !from_ds) {
        // Ad-hoc or management frame
        // addr1 = DA, addr2 = SA, addr3 = BSSID
        memcpy(pkt->dst_mac, hdr->addr1, 6);
        memcpy(pkt->src_mac, hdr->addr2, 6);
        memcpy(pkt->bssid, hdr->addr3, 6);
    } else if (to_ds && !from_ds) {
        // Station → AP
        // addr1 = BSSID, addr2 = SA, addr3 = DA
        memcpy(pkt->bssid, hdr->addr1, 6);
        memcpy(pkt->src_mac, hdr->addr2, 6);
        memcpy(pkt->dst_mac, hdr->addr3, 6);
    } else if (!to_ds && from_ds) {
        // AP → Station
        // addr1 = DA, addr2 = BSSID, addr3 = SA
        memcpy(pkt->dst_mac, hdr->addr1, 6);
        memcpy(pkt->bssid, hdr->addr2, 6);
        memcpy(pkt->src_mac, hdr->addr3, 6);
    } else {
        // WDS (Wireless Distribution System)
        // addr1 = RA, addr2 = TA, addr3 = DA, addr4 = SA
        memcpy(pkt->dst_mac, hdr->addr1, 6);
        memcpy(pkt->src_mac, hdr->addr2, 6);
        // BSSID not clearly defined in WDS
        memset(pkt->bssid, 0, 6);
    }

    return sizeof(struct wifi_mac_header);
}

// Parse beacon/probe response body
static void parse_beacon_body(const uint8_t *body, int body_len, struct parsed_packet *pkt) {
    if (body_len < 12) {
        return;
    }

    // Fixed parameters
    pkt->beacon_interval = ntohs(*(uint16_t *)(body + 8));
    pkt->capability = ntohs(*(uint16_t *)(body + 10));

    // Extract SSID
    pkt->ssid_len = extract_ssid(body, body_len, pkt->ssid, sizeof(pkt->ssid));
    if (pkt->ssid_len < 0) {
        pkt->ssid[0] = '\0';
        pkt->ssid_len = 0;
    }
}

// Detect EAPOL frames
static void detect_eapol(const uint8_t *frame, int length, struct parsed_packet *pkt) {
    // Check for LLC/SNAP header with EAPOL ethertype
    // LLC/SNAP: AA AA 03 00 00 00 88 8E
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

    // Parse radiotap header
    int rt_len = parse_radiotap(packet, length, &pkt);
    if (rt_len < 0) {
        return pkt; // Invalid radiotap
    }

    // Parse MAC header
    const uint8_t *frame = packet + rt_len;
    int frame_len = length - rt_len;

    int mac_len = parse_mac_header(frame, frame_len, &pkt);
    if (mac_len < 0) {
        return pkt; // Invalid MAC header
    }

    // Parse body based on frame type
    const uint8_t *body = frame + mac_len;
    int body_len = frame_len - mac_len;

    if (pkt.frame_type == WIFI_FRAME_TYPE_MANAGEMENT) {
        if (pkt.frame_subtype == WIFI_SUBTYPE_BEACON ||
            pkt.frame_subtype == WIFI_SUBTYPE_PROBE_RESP) {
            parse_beacon_body(body, body_len, &pkt);
        }
    } else if (pkt.frame_type == WIFI_FRAME_TYPE_DATA) {
        // Check for EAPOL
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

    // Print beacon-specific info
    if (pkt->frame_type == WIFI_FRAME_TYPE_MANAGEMENT) {
        if (pkt->frame_subtype == WIFI_SUBTYPE_BEACON ||
            pkt->frame_subtype == WIFI_SUBTYPE_PROBE_RESP) {
            printf("  SSID: %s | Channel: %d\n",
                   strlen(pkt->ssid) > 0 ? pkt->ssid : "(hidden)",
                   pkt->channel);
        }
    }

    // Print EAPOL detection
    if (pkt->is_eapol) {
        printf("  *** EAPOL DETECTED ***\n");
    }
}
