#include "crypto.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// WPA key expansion label
static const char *PTK_KEY_EXPANSION = "Pairwise key expansion";

// Hex dump for debugging
void crypto_hex_dump(const char *label, const uint8_t *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len) {
            printf("\n%*s", (int)strlen(label) + 2, "");
        }
    }
    printf("\n");
}

// Print PMK in hex
void crypto_print_pmk(const uint8_t *pmk) {
    crypto_hex_dump("PMK", pmk, WPA_PMK_LEN);
}

// Print PTK in hex
void crypto_print_ptk(const uint8_t *ptk) {
    crypto_hex_dump("PTK", ptk, WPA_PTK_LEN);
}

// Derive PMK from passphrase and SSID using PBKDF2
int crypto_derive_pmk(const char *passphrase, const char *ssid,
                      int ssid_len, uint8_t *pmk_out) {
    if (!passphrase || !ssid || !pmk_out) {
        return -1;
    }

    int passphrase_len = strlen(passphrase);

    // Use OpenSSL's PBKDF2
    int result = PKCS5_PBKDF2_HMAC(
        passphrase,         // Password
        passphrase_len,     // Password length
        (const uint8_t *)ssid,  // Salt (SSID)
        ssid_len,           // Salt length
        WPA_PBKDF2_ITERATIONS,  // Iterations
        EVP_sha1(),         // Hash function
        WPA_PMK_LEN,        // Output length (32 bytes)
        pmk_out             // Output buffer
    );

    if (result != 1) {
        log_error("PBKDF2 derivation failed");
        return -1;
    }

    return 0;
}

// PRF function used in PTK derivation
// PRF(K, A) = HMAC-SHA1(K, A || 0x00) || HMAC-SHA1(K, A || 0x01) || ...
static void prf(const uint8_t *key, int key_len,
                const uint8_t *data, int data_len,
                uint8_t *output, int output_len) {
    uint8_t buffer[256];
    uint8_t hmac[SHA_DIGEST_LENGTH];
    int iterations = (output_len + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;

    for (int i = 0; i < iterations; i++) {
        // Construct data: A || counter
        memcpy(buffer, data, data_len);
        buffer[data_len] = (uint8_t)i;

        // HMAC-SHA1
        unsigned int hmac_len = SHA_DIGEST_LENGTH;
        HMAC(EVP_sha1(),
             key, key_len,
             buffer, data_len + 1,
             hmac, &hmac_len);

        // Copy to output
        int copy_len = (output_len - i * SHA_DIGEST_LENGTH);
        if (copy_len > SHA_DIGEST_LENGTH) {
            copy_len = SHA_DIGEST_LENGTH;
        }
        memcpy(output + i * SHA_DIGEST_LENGTH, hmac, copy_len);
    }
}

// Derive PTK from PMK and handshake data
int crypto_derive_ptk(const uint8_t *pmk,
                      const uint8_t *aa,   // AP MAC
                      const uint8_t *spa,  // Client MAC
                      const uint8_t *anonce,
                      const uint8_t *snonce,
                      uint8_t *ptk_out) {
    if (!pmk || !aa || !spa || !anonce || !snonce || !ptk_out) {
        return -1;
    }

    // Construct the data for PTK derivation
    // PTK = PRF(PMK, "Pairwise key expansion",
    //           min(AA, SPA) || max(AA, SPA) || min(ANonce, SNonce) || max(ANonce, SNonce))

    uint8_t data[256];
    int data_len = 0;

    // Add label
    int label_len = strlen(PTK_KEY_EXPANSION);
    memcpy(data + data_len, PTK_KEY_EXPANSION, label_len);
    data_len += label_len;

    // Add null byte
    data[data_len++] = 0;

    // Add min(AA, SPA)
    if (memcmp(aa, spa, 6) < 0) {
        memcpy(data + data_len, aa, 6);
        data_len += 6;
        memcpy(data + data_len, spa, 6);
        data_len += 6;
    } else {
        memcpy(data + data_len, spa, 6);
        data_len += 6;
        memcpy(data + data_len, aa, 6);
        data_len += 6;
    }

    // Add min(ANonce, SNonce)
    if (memcmp(anonce, snonce, 32) < 0) {
        memcpy(data + data_len, anonce, 32);
        data_len += 32;
        memcpy(data + data_len, snonce, 32);
        data_len += 32;
    } else {
        memcpy(data + data_len, snonce, 32);
        data_len += 32;
        memcpy(data + data_len, anonce, 32);
        data_len += 32;
    }

    // Derive PTK using PRF
    prf(pmk, WPA_PMK_LEN, data, data_len, ptk_out, WPA_PTK_LEN);

    return 0;
}

// Calculate MIC for EAPOL frame
int crypto_calculate_mic(const uint8_t *ptk,
                         const uint8_t *eapol_frame,
                         int eapol_len,
                         uint8_t *mic_out) {
    if (!ptk || !eapol_frame || !mic_out) {
        return -1;
    }

    // The MIC is calculated over the EAPOL frame with the MIC field zeroed out
    // For WPA, we use the first 16 bytes of PTK as the key

    // Create a copy of the EAPOL frame with MIC field zeroed
    uint8_t frame_copy[256];
    if (eapol_len > sizeof(frame_copy)) {
        return -1;
    }
    memcpy(frame_copy, eapol_frame, eapol_len);

    // Zero out the MIC field (bytes 77-92 in EAPOL Key frame)
    // EAPOL header: 4 bytes (version, type, length)
    // Key descriptor: 2 bytes (type)
    // Key info: 2 bytes
    // Key length: 2 bytes
    // Replay counter: 8 bytes
    // Nonce: 32 bytes
    // IV: 16 bytes
    // Key RSC: 8 bytes
    // Key ID: 8 bytes
    // MIC: 16 bytes (offset 77 from start of EAPOL frame)
    if (eapol_len >= 93) {
        memset(frame_copy + 77, 0, 16);
    }

    // Calculate HMAC-SHA1-128
    unsigned int hmac_len = SHA_DIGEST_LENGTH;
    uint8_t hmac[SHA_DIGEST_LENGTH];

    HMAC(EVP_sha1(),
         ptk, 16,           // Key: first 16 bytes of PTK
         frame_copy, eapol_len,
         hmac, &hmac_len);

    // Copy first 16 bytes as MIC
    memcpy(mic_out, hmac, WPA_MIC_LEN);

    return 0;
}

// Verify MIC on EAPOL frame
int crypto_verify_mic(const uint8_t *ptk,
                      const uint8_t *eapol_frame,
                      int eapol_len,
                      const uint8_t *expected_mic) {
    if (!ptk || !eapol_frame || !expected_mic) {
        return -1;
    }

    uint8_t calculated_mic[WPA_MIC_LEN];

    if (crypto_calculate_mic(ptk, eapol_frame, eapol_len, calculated_mic) < 0) {
        return -1;
    }

    // Compare calculated MIC with expected MIC
    if (memcmp(calculated_mic, expected_mic, WPA_MIC_LEN) == 0) {
        return 1;  // Match
    }

    return 0;  // No match
}
