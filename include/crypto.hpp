#pragma once

#include "footer.hpp"
#include <array>
#include <cstdint>

// ---------------------------------------------------------------------------
// crypto — thin OpenSSL AES-128-CMAC wrapper
//
// The 16-byte key is set once at startup (or per-session in a real system).
// All functions are thread-safe since they only read the key.
// ---------------------------------------------------------------------------

namespace crypto {

// Set the shared 16-byte AES key used for sign/verify.
// Must be called before any sign_message() / verify_message() call.
void set_key(const std::array<uint8_t, 16>& key);

// Compute AES-128-CMAC over (payload || footer metadata) and write the
// 16-byte tag into footer.mac.  The MAC covers:
//   - payload_len bytes of application data
//   - footer.domain_id  (2 bytes)
//   - footer.method_id  (2 bytes)
// This prevents an attacker from replaying a valid tag with different metadata.
void sign_message(const uint8_t* payload, size_t payload_len, OMacFooter& footer);

// Recompute the tag and compare with CRYPTO_memcmp (timing-safe).
// Returns true  → footer is authentic.
// Returns false → MAC mismatch or any OpenSSL error.
bool verify_message(const uint8_t* payload, size_t payload_len, const OMacFooter& footer);

} // namespace crypto
