//
// test_flows.cpp — end-to-end integration test for the reference monitor
//
// Tests the complete security stack without vsomeip:
//   crypto::sign_message → footer_append → ReferenceMonitor::check()
//
// Build:
//   g++ -std=c++17 -I../include \
//       ../src/crypto.cpp ../src/automaton.cpp ../src/reference_monitor.cpp \
//       test_flows.cpp -lssl -lcrypto -o test_flows && ./test_flows
//

#include "reference_monitor.hpp"
#include "crypto.hpp"
#include "footer.hpp"

#include <array>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

// Shared AES-128 key — same key installed on every ECU in the demo
static const std::array<uint8_t, 16> DEMO_KEY = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const std::string POLICY = "policies/tcu_rd_rc_policy.json";

// ---------------------------------------------------------------------------
// Helper: build a signed payload buffer ready to hand to the monitor.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> make_signed_message(const std::string& app_data,
                                                 uint16_t domain_id,
                                                 uint16_t method_id)
{
    std::vector<uint8_t> buf(app_data.begin(), app_data.end());

    OMacFooter footer;
    footer.domain_id = domain_id;
    footer.method_id = method_id;

    crypto::sign_message(buf.data(), buf.size(), footer);
    footer_append(buf, footer);
    return buf;
}

// ---------------------------------------------------------------------------
// F1 — Full Remote Diagnostic: NAD→RD→Diag
// Both hops must be ALLOWED; monitor ends in idle.
// ---------------------------------------------------------------------------
static void test_flow_F1_remote_diagnostic(ReferenceMonitor& monitor)
{
    // Hop 1: NAD::4G calls AppuP::RD
    auto buf1 = make_signed_message("RD_SESSION_REQUEST", 0x0001, 0x0001);
    bool r1 = monitor.check(buf1, "NAD::4G", "AppuP::RD", "invoke_RD");
    assert(r1 && "F1-a: NAD→AppuP::RD must be allowed");

    // Hop 2: AppuP::RD forwards to SafetyuC::Diag
    auto buf2 = make_signed_message("DIAG_PAYLOAD", 0x0002, 0x0003);
    bool r2 = monitor.check(buf2, "AppuP::RD", "SafetyuC::Diag", "invoke_Diag");
    assert(r2 && "F1-b: AppuP::RD→SafetyuC::Diag must be allowed");

    assert(monitor.current_state() == "idle" && "F1 should end in idle");
    std::cout << "[PASS] F1: Full Remote Diagnostic flow — both hops ALLOWED\n";
}

// ---------------------------------------------------------------------------
// Flow 2 (paper legit) — Full Remote Control: NAD→RC→Ctrl
// Both hops must be ALLOWED; monitor ends in idle.
// ---------------------------------------------------------------------------
static void test_flow_F2_remote_control(ReferenceMonitor& monitor)
{
    auto buf1 = make_signed_message("RC_SESSION_REQUEST", 0x0001, 0x0002);
    bool r1 = monitor.check(buf1, "NAD::4G", "AppuP::RC", "invoke_RC");
    assert(r1 && "F2-a: NAD→AppuP::RC must be allowed");

    auto buf2 = make_signed_message("CTRL_PAYLOAD", 0x0002, 0x0004);
    bool r2 = monitor.check(buf2, "AppuP::RC", "SafetyuC::Ctrl", "invoke_Ctrl");
    assert(r2 && "F2-b: AppuP::RC→SafetyuC::Ctrl must be allowed");

    assert(monitor.current_state() == "idle" && "F2 should end in idle");
    std::cout << "[PASS] Flow F2: Full Remote Control flow — both hops ALLOWED\n";
}

// ---------------------------------------------------------------------------
// Attack F3 — RC tries to invoke Diag (privilege escalation)
// After NAD→RC (allowed), AppuP::RC must NOT be able to call SafetyuC::Diag.
// ---------------------------------------------------------------------------
static void test_attack_F3_rc_calls_diag(ReferenceMonitor& monitor)
{
    // First hop is legitimate
    auto buf1 = make_signed_message("RC_SESSION_REQUEST", 0x0001, 0x0002);
    bool r1 = monitor.check(buf1, "NAD::4G", "AppuP::RC", "invoke_RC");
    assert(r1 && "F3 setup: NAD→AppuP::RC must be allowed");

    // Attacker now tries to pivot: RC calls Diag
    auto buf2 = make_signed_message("DIAG_EXPLOIT", 0x0002, 0x0003);
    bool r2 = monitor.check(buf2, "AppuP::RC", "SafetyuC::Diag", "invoke_Diag");
    assert(!r2 && "F3: AppuP::RC→SafetyuC::Diag must be BLOCKED");

    // State must not have advanced
    assert(monitor.current_state() == "nad_called_rc" && "F3: state must remain nad_called_rc");
    monitor.reset();
    std::cout << "[PASS] Attack F3: RC→Diag privilege escalation BLOCKED\n";
}

// ---------------------------------------------------------------------------
// Attack F4 — GPS interface tries to invoke RD (unauthorized sender)
// ---------------------------------------------------------------------------
static void test_attack_F4_gps_invokes_rd(ReferenceMonitor& monitor)
{
    auto buf = make_signed_message("GPS_SPOOF", 0x0005, 0x0001);
    bool r = monitor.check(buf, "NAD::GPS", "AppuP::RD", "invoke_RD");
    assert(!r && "F4: NAD::GPS→AppuP::RD must be BLOCKED");
    assert(monitor.current_state() == "idle" && "F4: state must remain idle");
    std::cout << "[PASS] Attack F4: GPS→RD unauthorized sender BLOCKED\n";
}

// ---------------------------------------------------------------------------
// No footer — message without an OMacFooter must be dropped immediately.
// ---------------------------------------------------------------------------
static void test_no_footer_blocked(ReferenceMonitor& monitor)
{
    std::vector<uint8_t> bare_payload = {0x01, 0x02, 0x03, 0x04};  // no footer
    bool r = monitor.check(bare_payload, "NAD::4G", "AppuP::RD", "invoke_RD");
    assert(!r && "Message without footer must be BLOCKED");
    std::cout << "[PASS] Missing footer: message immediately BLOCKED\n";
}

// ---------------------------------------------------------------------------
// Tampered payload — valid footer, corrupted body → MAC fails.
// ---------------------------------------------------------------------------
static void test_tampered_payload_blocked(ReferenceMonitor& monitor)
{
    auto buf = make_signed_message("LEGITIMATE_DATA", 0x0001, 0x0001);

    // Flip a byte in the application data (before the footer)
    buf[0] ^= 0xFF;

    bool r = monitor.check(buf, "NAD::4G", "AppuP::RD", "invoke_RD");
    assert(!r && "Tampered payload must be BLOCKED by MAC check");
    std::cout << "[PASS] Tampered payload: MAC mismatch BLOCKED\n";
}

// ---------------------------------------------------------------------------
int main()
{
    crypto::set_key(DEMO_KEY);

    std::cout << "=== test_flows — full integration ===\n\n";

    // Each test function reuses or resets the same monitor to show state continuity
    ReferenceMonitor monitor(POLICY);

    std::cout << "-- Legitimate flows --\n";
    test_flow_F1_remote_diagnostic(monitor);
    test_flow_F2_remote_control(monitor);

    std::cout << "\n-- Attack scenarios --\n";
    test_attack_F3_rc_calls_diag(monitor);
    test_attack_F4_gps_invokes_rd(monitor);
    test_no_footer_blocked(monitor);
    test_tampered_payload_blocked(monitor);

    std::cout << "\nAll integration tests passed.\n";
    return 0;
}
