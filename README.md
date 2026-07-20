# WiFi WPA Handshake Cracker

An educational WiFi security testing tool built from scratch in C. This tool is designed for learning purposes to understand how WiFi security works and how vulnerabilities can be exploited.

## ⚠️ Legal Disclaimer

**This tool is for educational purposes only.** Only use on networks you own or have explicit written permission to test. Unauthorized access to computer networks is illegal and unethical.

## Features

- ✅ Auto-detect wireless interfaces
- ✅ Monitor mode activation
- ✅ Raw packet capture with AF_PACKET
- ✅ 802.11 frame parsing (beacons, probes, EAPOL)
- ✅ WPA 4-way handshake extraction
- ✅ Dictionary attack with rockyou.txt
- ✅ OpenSSL integration for PBKDF2/AES
- ✅ Progress tracking and statistics
- ✅ Signal handling and cleanup

## Prerequisites

### Kali Linux / Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev libnl-3-dev libnl-genl-3-dev
```

### Arch Linux

```bash
sudo pacman -S base-devel openssl libnl
```

## Building

```bash
# Clone or download the project
cd wifi-cracker

# Build
make

# Or build with debug symbols
make debug
```

## Usage

```bash
# Auto-detect interface and crack
sudo ./wifocrack -w /usr/share/wordlists/rockyou.txt

# Specify interface
sudo ./wifocrack -i wlan0 -w /usr/share/wordlists/rockyou.txt

# Specify target BSSID
sudo ./wifocrack -i wlan0 -b AA:BB:CC:DD:EE:FF -w rockyou.txt

# Scan only (no cracking)
sudo ./wifocrack -i wlan0 -s

# Specify channel
sudo ./wifocrack -i wlan0 -c 6 -w rockyou.txt
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --interface NAME` | Specify wireless interface (auto-detect if not provided) |
| `-b, --bssid MAC` | Target AP MAC address (XX:XX:XX:XX:XX:XX format) |
| `-w, --wordlist PATH` | Path to wordlist file (required for cracking) |
| `-c, --channel NUM` | Specific channel to scan (1-14, default: all) |
| `-s, --scan-only` | Only scan for networks (no handshake capture) |
| `-v, --version` | Show version information |
| `-h, --help` | Show help message |

## Project Structure

```
wifi-cracker/
├── src/
│   ├── main.c              # Entry point, CLI, orchestration
│   ├── interface.c/h       # Auto-detect WiFi interfaces
│   ├── monitor.c/h         # Monitor mode activation
│   ├── capture.c/h         # Raw packet capture
│   ├── parser.c/h          # 802.11 frame parsing
│   ├── handshake.c/h       # WPA handshake extraction
│   ├── scanner.c/h         # Channel hopping + AP discovery
│   ├── crypto.c/h          # OpenSSL PBKDF2 + AES
│   ├── cracker.c/h         # Dictionary attack engine
│   └── utils.c/h           # Helper functions
├── Makefile
├── README.md
├── PLAN.md                 # Implementation plan
└── wordlists/
    └── rockyou.txt          # User provides this file
```

## Implementation Status

- [x] Phase 1: Interface detection + Monitor mode - **COMPLETE**
- [x] Phase 2: Raw socket capture + Channel hopping - **COMPLETE**
- [x] Phase 3: 802.11 frame parsing - **COMPLETE**
- [x] Phase 4: WPA handshake extraction - **COMPLETE**
- [x] Phase 5: Crypto (OpenSSL PBKDF2 + AES) - **COMPLETE**
- [x] Phase 6: Dictionary attack engine - **COMPLETE**
- [x] Phase 7: Main orchestration + polish - **COMPLETE**

## How It Works

1. **Interface Detection**: Scans `/sys/class/net/` for wireless interfaces
2. **Monitor Mode**: Puts interface into monitor mode using `iw` or `iwconfig`
3. **Channel Hopping**: Scans channels 1-14 with configurable dwell time
4. **Packet Capture**: Uses `AF_PACKET` raw sockets to capture WiFi traffic
5. **Frame Parsing**: Parses 802.11 radiotap and management/data frames
6. **Handshake Detection**: Identifies EAPOL frames (WPA 4-way handshake)
7. **Key Derivation**: Uses PBKDF2 to derive PMK, then PTK
8. **Dictionary Attack**: Tests each word against the captured handshake

## Technical Details

### WPA Handshake

The WPA 4-way handshake consists of:
- Message 1: AP → Client (ANonce)
- Message 2: Client → AP (SNonce + MIC)
- Message 3: AP → Client (GTK + MIC)
- Message 4: Client → AP (ACK)

### Key Derivation

```
PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096, 32)
PTK = PRF-512(PMK, "Pairwise key expansion", ...)
MIC = HMAC-SHA1(PTK[0:16], EAPOL_Frame)
```

## Output Example

```
╔══════════════════════════════════════════════════════════════╗
║         WiFi WPA Handshake Cracker v1.0.0                   ║
║         Educational Purpose Only                             ║
╚══════════════════════════════════════════════════════════════╝

[+] Configuration:
[+]   Interface:  wlan0
[+]   Target BSSID: (any)
[+]   Wordlist:   /usr/share/wordlists/rockyou.txt
[+]   Channel:    all (1-14)
[+]   Mode:       Handshake capture + crack

[*] Starting capture... (Press Ctrl+C to stop)

╔══════════════════════════════════════════════════════════════╗
║                    Discovered Access Points                  ║
╠══════════════════════════════════════════════════════════════╣
║  BSSID              Signal  Ch  SSID                         ║
╠══════════════════════════════════════════════════════════════╣
║  AA:BB:CC:DD:EE:FF   -45 dBm   6  MyNetwork                 ║
╚══════════════════════════════════════════════════════════════╝

[+] WPA handshake captured!
[+] Password found: password123
[+] Tried 1234 passwords in 5.67 seconds (218 p/s)
```

## Resources

- [IEEE 802.11 Standard](https://en.wikipedia.org/wiki/IEEE_802.11)
- [WPA Handshake Explained](https://www.wirelesslanprofessional.com/wp-content/uploads/2014/01/WPA-Handshake.pdf)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Linux AF_PACKET Sockets](https://man7.org/linux/man-pages/man7/packet.7.html)

## License

This project is for educational purposes only. Use responsibly.
