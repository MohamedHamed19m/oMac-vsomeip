//
// test_crypto.cpp — unit tests for AES-128-CMAC sign/verify
//
// Build:
//   g++ -std=c++17 -I../include ../src/crypto.cpp test_crypto.cpp \
//       -lssl -lcrypto -o test_crypto && ./test_crypto
//

#include "crypto.hpp"
#include "footer.hpp"

#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

// Shared test key — 16 zero bytes (simple KAT anchor)
static const std::array<uint8_t, 16> TEST_KEY = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// ---------------------------------------------------------------------------
static void test_sign_verify_roundtrip()
{
    crypto::set_key(TEST_KEY);

    std::vector<uint8_t> payload = {0x48, 0x65, 0x6c, 0x6c, 0x6f};  // "Hello"

    OMacFooter footer;
    footer.domain_id = 0x0001;
    footer.method_id = 0x0002;

    crypto::sign_message(payload.data(), payload.size(), footer);

    bool ok = crypto::verify_message(payload.data(), payload.size(), footer);
    assert(ok);
    std::cout << "[PASS] sign → verify round-trip succeeds\n";
}

// ---------------------------------------------------------------------------
static void test_tampered_payload_fails()
{
    crypto::set_key(TEST_KEY);

    std::vector<uint8_t> payload = {0x01, 0x02, 0x03};

    OMacFooter footer;
    footer.domain_id = 0x0010;
    footer.method_id = 0x0020;

    crypto::sign_message(payload.data(), payload.size(), footer);

    // Flip one bit in the payload
    payload[1] ^= 0x01;

    bool ok = crypto::verify_message(payload.data(), payload.size(), footer);
    assert(!ok);
    std::cout << "[PASS] tampered payload causes verify to return false\n";
}

// ---------------------------------------------------------------------------
static void test_tampered_mac_fails()
{
    crypto::set_key(TEST_KEY);

    std::vector<uint8_t> payload = {0xAA, 0xBB};

    OMacFooter footer;
    footer.domain_id = 0x0001;
    footer.method_id = 0x0001;

    crypto::sign_message(payload.data(), payload.size(), footer);

    // Corrupt the MAC tag
    footer.mac[0] ^= 0xFF;

    bool ok = crypto::verify_message(payload.data(), payload.size(), footer);
    assert(!ok);
    std::cout << "[PASS] tampered MAC tag causes verify to return false\n";
}

// ---------------------------------------------------------------------------
static void test_different_metadata_fails()
{
    crypto::set_key(TEST_KEY);

    std::vector<uint8_t> payload = {0x11, 0x22, 0x33};

    OMacFooter footer;
    footer.domain_id = 0x0001;
    footer.method_id = 0x0001;
    crypto::sign_message(payload.data(), payload.size(), footer);

    // Attacker changes metadata but keeps the MAC from the original message
    footer.method_id = 0x0002;

    bool ok = crypto::verify_message(payload.data(), payload.size(), footer);
    assert(!ok);
    std::cout << "[PASS] metadata change invalidates the existing MAC tag\n";
}

// ---------------------------------------------------------------------------
int main()
{
    std::cout << "=== test_crypto ===\n";
    test_sign_verify_roundtrip();
    test_tampered_payload_fails();
    test_tampered_mac_fails();
    test_different_metadata_fails();
    std::cout << "All crypto tests passed.\n";
    return 0;
}
