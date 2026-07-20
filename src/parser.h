#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <linux/if_ether.h>

// 802.11 Frame Types
#define WIFI_FRAME_TYPE_MANAGEMENT  0x00
#define WIFI_FRAME_TYPE_CONTROL     0x01
#define WIFI_FRAME_TYPE_DATA        0x02

// Management Frame Subtypes
#define WIFI_SUBTYPE_BEACON         0x08
#define WIFI_SUBTYPE_PROBE_REQ      0x04
#define WIFI_SUBTYPE_PROBE_RESP     0x05
#define WIFI_SUBTYPE_AUTH           0x0B
#define WIFI_SUBTYPE_DEAUTH         0x0C
#define WIFI_SUBTYPE_ASSOC_REQ      0x00
#define WIFI_SUBTYPE_ASSOC_RESP     0x01

// Data Frame Subtypes
#define WIFI_SUBTYPE_DATA           0x00
#define WIFI_SUBTYPE_DATA_CF_ACK    0x01
#define WIFI_SUBTYPE_DATA_CF_POLL   0x02
#define WIFI_SUBTYPE_NULL           0x04

// EAPOL ethertype
#define ETHERTYPE_EAPOL             0x888e

// Radiotap header (simplified)
struct radiotap_header {
    uint8_t  version;
    uint8_t  pad;
    uint16_t length;
    uint32_t present;
} __attribute__((packed));

// 802.11 Frame Control field
struct wifi_frame_control {
    uint16_t protocol_version : 2;
    uint16_t type             : 2;
    uint16_t subtype          : 4;
    uint16_t to_ds            : 1;
    uint16_t from_ds          : 1;
    uint16_t more_frag        : 1;
    uint16_t retry            : 1;
    uint16_t power_mgmt       : 1;
    uint16_t more_data        : 1;
    uint16_t protected_frame  : 1;
    uint16_t order            : 1;
} __attribute__((packed));

// 802.11 MAC Header (simplified, without addresses 3/4)
struct wifi_mac_header {
    struct wifi_frame_control fc;
    uint16_t duration_id;
    uint8_t  addr1[6];  // Receiver Address (RA)
    uint8_t  addr2[6];  // Transmitter Address (TA)
    uint8_t  addr3[6];  // BSSID (for management/data frames)
    uint16_t seq_ctrl;
} __attribute__((packed));

// Beacon frame body (simplified)
struct wifi_beacon {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability_info;
    // Followed by Information Elements (IEs)
} __attribute__((packed));

// Probe Response frame body (similar to beacon)
struct wifi_probe_resp {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability_info;
    // Followed by Information Elements (IEs)
} __attribute__((packed));

// Parsed packet information
struct parsed_packet {
    int valid;                      // 1 if successfully parsed
    int channel;                    // Channel from radiotap (if present)

    // Frame info
    uint16_t frame_type;            // Management/Control/Data
    uint16_t frame_subtype;         // Subtype
    int is_protected;               // 1 if encrypted

    // MAC addresses
    uint8_t src_mac[6];             // Source address
    uint8_t dst_mac[6];             // Destination address
    uint8_t bssid[6];               // BSSID (AP MAC)

    // Beacon/Probe specific
    char ssid[64];                  // Network name
    int ssid_len;                   // SSID length
    uint16_t beacon_interval;       // Beacon interval (TU)
    uint32_t capability;            // Capability info

    // Signal info (from radiotap)
    int8_t signal_dbm;              // Signal strength in dBm
    int has_signal;                 // 1 if signal info available

    // EAPOL detection
    int is_eapol;                   // 1 if EAPOL frame
    uint16_t eapol_type;            // EAPOL type

    // Raw data
    const uint8_t *raw_data;        // Pointer to original packet
    int raw_len;                    // Original packet length
};

// Initialize parser
void parser_init(void);

// Parse a raw packet
// Returns parsed_packet structure
struct parsed_packet parse_packet(const uint8_t *packet, int length);

// Get frame type name
const char* get_frame_type_name(uint16_t type);

// Get frame subtype name
const char* get_frame_subtype_name(uint16_t type, uint16_t subtype);

// Print parsed packet info
void print_parsed_packet(const struct parsed_packet *pkt);

// Get SSID from beacon/probe response
// Returns length of SSID, or -1 on error
int extract_ssid(const uint8_t *frame_body, int body_len, char *ssid_out, int ssid_max_len);

#endif // PARSER_H
