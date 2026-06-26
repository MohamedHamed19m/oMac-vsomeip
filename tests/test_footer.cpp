//
// test_footer.cpp — unit tests for OMacFooter layout and helpers
//
// Build standalone (no vsomeip, no OpenSSL):
//   g++ -std=c++17 -I../include test_footer.cpp -o test_footer && ./test_footer
//

#include "footer.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

// ---------------------------------------------------------------------------
static void test_size()
{
    static_assert(sizeof(OMacFooter) == 24, "footer size regression");
    std::cout << "[PASS] sizeof(OMacFooter) == 24\n";
}

// ---------------------------------------------------------------------------
static void test_magic_default()
{
    OMacFooter f;
    assert(f.magic == OMAC_MAGIC);
    std::cout << "[PASS] default magic is OMAC_MAGIC\n";
}

// ---------------------------------------------------------------------------
static void test_append_and_present()
{
    std::vector<uint8_t> buf = {0x01, 0x02, 0x03, 0x04};  // 4 application bytes

    OMacFooter f;
    f.domain_id = 0x0A;
    f.method_id = 0x0B;
    footer_append(buf, f);

    assert(buf.size() == 4 + 24);
    assert(footer_present(buf));
    std::cout << "[PASS] footer_append adds 24 bytes and footer_present detects it\n";
}

// ---------------------------------------------------------------------------
static void test_not_present_on_short_buffer()
{
    std::vector<uint8_t> buf(10, 0x00);  // too small, no magic
    assert(!footer_present(buf));
    std::cout << "[PASS] footer_present returns false for short / no-magic buffer\n";
}

// ---------------------------------------------------------------------------
static void test_extract_roundtrip()
{
    std::vector<uint8_t> buf = {0xDE, 0xAD, 0xBE, 0xEF};

    OMacFooter orig;
    orig.domain_id = 0x1234;
    orig.method_id = 0x5678;
    std::memset(orig.mac, 0xAB, 16);
    footer_append(buf, orig);

    OMacFooter got = footer_extract(buf);
    assert(got.magic     == orig.magic);
    assert(got.domain_id == orig.domain_id);
    assert(got.method_id == orig.method_id);
    assert(std::memcmp(got.mac, orig.mac, 16) == 0);
    std::cout << "[PASS] footer_extract round-trip preserves all fields\n";
}

// ---------------------------------------------------------------------------
static void test_payload_without_footer()
{
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03};
    std::vector<uint8_t> buf = payload;
    footer_append(buf, OMacFooter{});

    auto recovered = payload_without_footer(buf);
    assert(recovered == payload);
    std::cout << "[PASS] payload_without_footer strips exactly the footer bytes\n";
}

// ---------------------------------------------------------------------------
int main()
{
    std::cout << "=== test_footer ===\n";
    test_size();
    test_magic_default();
    test_append_and_present();
    test_not_present_on_short_buffer();
    test_extract_roundtrip();
    test_payload_without_footer();
    std::cout << "All footer tests passed.\n";
    return 0;
}
