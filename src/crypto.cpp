#include "crypto.hpp"

#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace crypto {

// ---------------------------------------------------------------------------
// Shared AES-128 key (16 bytes).  Set once via set_key() before use.
// ---------------------------------------------------------------------------
static std::array<uint8_t, 16> g_key = {};
static bool g_key_set = false;

void set_key(const std::array<uint8_t, 16>& key)
{
    g_key     = key;
    g_key_set = true;
}

// ---------------------------------------------------------------------------
// Internal: compute CMAC over arbitrary data.
// Returns a 16-byte tag, or throws on OpenSSL failure.
// ---------------------------------------------------------------------------
static std::array<uint8_t, 16> compute_cmac(const std::vector<uint8_t>& data)
{
    if (!g_key_set)
        throw std::runtime_error("crypto::set_key() must be called before signing");

    CMAC_CTX* ctx = CMAC_CTX_new();
    if (!ctx)
        throw std::runtime_error("CMAC_CTX_new failed");

    if (CMAC_Init(ctx, g_key.data(), g_key.size(), EVP_aes_128_cbc(), nullptr) != 1) {
        CMAC_CTX_free(ctx);
        throw std::runtime_error("CMAC_Init failed");
    }

    if (CMAC_Update(ctx, data.data(), data.size()) != 1) {
        CMAC_CTX_free(ctx);
        throw std::runtime_error("CMAC_Update failed");
    }

    std::array<uint8_t, 16> tag = {};
    size_t tag_len = 16;
    if (CMAC_Final(ctx, tag.data(), &tag_len) != 1) {
        CMAC_CTX_free(ctx);
        throw std::runtime_error("CMAC_Final failed");
    }

    CMAC_CTX_free(ctx);
    return tag;
}

// ---------------------------------------------------------------------------
// Build the MAC input buffer: payload bytes + domain_id LE + method_id LE.
// Including the footer metadata fields in the MAC prevents an attacker from
// reusing a valid tag with different domain/method values.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> build_mac_input(const uint8_t* payload,
                                             size_t         payload_len,
                                             const OMacFooter& footer)
{
    std::vector<uint8_t> input(payload, payload + payload_len);
    // append domain_id as two little-endian bytes
    input.push_back(static_cast<uint8_t>(footer.domain_id & 0xFF));
    input.push_back(static_cast<uint8_t>((footer.domain_id >> 8) & 0xFF));
    // append method_id as two little-endian bytes
    input.push_back(static_cast<uint8_t>(footer.method_id & 0xFF));
    input.push_back(static_cast<uint8_t>((footer.method_id >> 8) & 0xFF));
    return input;
}

// ---------------------------------------------------------------------------
// sign_message: compute CMAC and write the tag into footer.mac.
// ---------------------------------------------------------------------------
void sign_message(const uint8_t* payload, size_t payload_len, OMacFooter& footer)
{
    auto input = build_mac_input(payload, payload_len, footer);
    auto tag   = compute_cmac(input);
    std::memcpy(footer.mac, tag.data(), 16);
}

// ---------------------------------------------------------------------------
// verify_message: recompute CMAC and compare timing-safely.
// ---------------------------------------------------------------------------
bool verify_message(const uint8_t* payload, size_t payload_len, const OMacFooter& footer)
{
    try {
        auto input    = build_mac_input(payload, payload_len, footer);
        auto expected = compute_cmac(input);
        // CRYPTO_memcmp returns 0 when equal — timing-safe comparison
        return (CRYPTO_memcmp(expected.data(), footer.mac, 16) == 0);
    } catch (...) {
        return false;
    }
}

} // namespace crypto
