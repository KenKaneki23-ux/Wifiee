#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

// WPA constants
#define WPA_PMK_LEN       32
#define WPA_PTK_LEN       64
#define WPA_PTK_LEN_MIN   32
#define WPA_MIC_LEN       16
#define WPA_NONCE_LEN     32
#define WPA_REPLAY_LEN    8

// PBKDF2 iteration count for WPA
#define WPA_PBKDF2_ITERATIONS 4096

// Derive PMK from passphrase and SSID
// PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096, 32)
// Returns 0 on success, -1 on failure
int crypto_derive_pmk(const char *passphrase, const char *ssid,
                      int ssid_len, uint8_t *pmk_out);

// Derive PTK from PMK, ANonce, SNonce, AP MAC, Client MAC
// PTK = PRF-512(PMK, "Pairwise key expansion", ...)
// Returns 0 on success, -1 on failure
int crypto_derive_ptk(const uint8_t *pmk,
                      const uint8_t *aa,   // AP MAC
                      const uint8_t *spa,  // Client MAC
                      const uint8_t *anonce,
                      const uint8_t *snonce,
                      uint8_t *ptk_out);

// Verify MIC on EAPOL frame
// MIC = HMAC-SHA1(PTK[0:16], EAPOL_Frame)
// Returns 1 if MIC matches, 0 if not, -1 on error
int crypto_verify_mic(const uint8_t *ptk,
                      const uint8_t *eapol_frame,
                      int eapol_len,
                      const uint8_t *expected_mic);

// Calculate MIC for EAPOL frame
// Returns 0 on success, -1 on failure
int crypto_calculate_mic(const uint8_t *ptk,
                         const uint8_t *eapol_frame,
                         int eapol_len,
                         uint8_t *mic_out);

// Hex dump for debugging
void crypto_hex_dump(const char *label, const uint8_t *data, int len);

// Print PMK in hex
void crypto_print_pmk(const uint8_t *pmk);

// Print PTK in hex
void crypto_print_ptk(const uint8_t *ptk);

#endif // CRYPTO_H
