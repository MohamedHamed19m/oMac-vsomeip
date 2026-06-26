//
// test_automaton.cpp — unit tests for SimpleAutomaton policy logic
//
// These tests run WITHOUT vsomeip or OpenSSL — pure state machine verification.
// Build:
//   g++ -std=c++17 -I../include ../src/automaton.cpp test_automaton.cpp \
//       -o test_automaton && ./test_automaton
//

#include "automaton.hpp"

#include <cassert>
#include <iostream>
#include <string>

static const std::string POLICY = "policies/tcu_rd_rc_policy.json";

// Convenience key builders
static std::string k(const std::string& f, const std::string& t, const std::string& m)
{
    return SimpleAutomaton::make_key(f, t, m);
}

// ---------------------------------------------------------------------------
// F1: NAD→RD→Diag — the happy path (Remote Diagnostic)
// Expected: ALLOW ALLOW, end state = idle
// ---------------------------------------------------------------------------
static void test_F1_remote_diagnostic_allowed()
{
    SimpleAutomaton a;
    a.load_from_json(POLICY);

    // Step 1: NAD::4G → AppuP::RD via invoke_RD  (idle → nad_called_rd)
    bool r1 = a.process_event(k("NAD::4G", "AppuP::RD", "invoke_RD"));
    assert(r1);
    assert(a.current_state == "nad_called_rd");

    // Step 2: AppuP::RD → SafetyuC::Diag via invoke_Diag  (nad_called_rd → idle)
    bool r2 = a.process_event(k("AppuP::RD", "SafetyuC::Diag", "invoke_Diag"));
    assert(r2);
    assert(a.current_state == "idle");

    std::cout << "[PASS] F1: Full Remote Diagnostic flow allowed\n";
}

// ---------------------------------------------------------------------------
// Flow 2 (paper): NAD→RC→Ctrl — the happy path (Remote Control)
// Expected: ALLOW ALLOW, end state = idle
// ---------------------------------------------------------------------------
static void test_F2_remote_control_allowed()
{
    SimpleAutomaton a;
    a.load_from_json(POLICY);

    bool r1 = a.process_event(k("NAD::4G", "AppuP::RC", "invoke_RC"));
    assert(r1);
    assert(a.current_state == "nad_called_rc");

    bool r2 = a.process_event(k("AppuP::RC", "SafetyuC::Ctrl", "invoke_Ctrl"));
    assert(r2);
    assert(a.current_state == "idle");

    std::cout << "[PASS] F2: Full Remote Control flow allowed\n";
}

// ---------------------------------------------------------------------------
// Attack F2 (paper): RC without a preceding RD session
// i.e. NAD skips RD and directly invokes RC, then tries Ctrl from idle
// Expected: BLOCK on the Ctrl call because RC was never sequenced from RD
// ---------------------------------------------------------------------------
static void test_attack_F2_rc_without_rd_blocked()
{
    SimpleAutomaton a;
    a.load_from_json(POLICY);

    // Attacker tries to skip the RD handshake and go straight to RC
    // invoke_RC from idle IS allowed (state → nad_called_rc)
    bool r1 = a.process_event(k("NAD::4G", "AppuP::RC", "invoke_RC"));
    assert(r1);  // first step is valid

    // But now the attacker tries to invoke_Diag instead of invoke_Ctrl
    // This is the "RC calls Diag" attack (paper's blocked flow F3)
    bool r2 = a.process_event(k("AppuP::RC", "SafetyuC::Diag", "invoke_Diag"));
    assert(!r2);  // BLOCK
    assert(a.current_state == "nad_called_rc");  // state unchanged

    std::cout << "[PASS] Attack F2/F3: RC→Diag call blocked\n";
}

// ---------------------------------------------------------------------------
// Attack F4: GPS interface tries to invoke RD
// Expected: BLOCK — GPS is not an authorised component
// ---------------------------------------------------------------------------
static void test_attack_F4_gps_invoke_rd_blocked()
{
    SimpleAutomaton a;
    a.load_from_json(POLICY);

    bool r = a.process_event(k("NAD::GPS", "AppuP::RD", "invoke_RD"));
    assert(!r);
    assert(a.current_state == "idle");  // state unchanged

    std::cout << "[PASS] Attack F4: GPS→RD call blocked\n";
}

// ---------------------------------------------------------------------------
// reset() brings the automaton back to its initial state
// ---------------------------------------------------------------------------
static void test_reset()
{
    SimpleAutomaton a;
    a.load_from_json(POLICY);

    a.process_event(k("NAD::4G", "AppuP::RD", "invoke_RD"));
    assert(a.current_state == "nad_called_rd");

    a.reset();
    assert(a.current_state == "idle");

    std::cout << "[PASS] reset() returns automaton to idle\n";
}

// ---------------------------------------------------------------------------
// Completely unknown event is blocked in any state
// ---------------------------------------------------------------------------
static void test_unknown_event_blocked()
{
    SimpleAutomaton a;
    a.load_from_json(POLICY);

    bool r = a.process_event("unknown::component::unknown_method");
    assert(!r);
    std::cout << "[PASS] Unknown event blocked in idle state\n";
}

// ---------------------------------------------------------------------------
int main()
{
    std::cout << "=== test_automaton ===\n";
    test_F1_remote_diagnostic_allowed();
    test_F2_remote_control_allowed();
    test_attack_F2_rc_without_rd_blocked();
    test_attack_F4_gps_invoke_rd_blocked();
    test_reset();
    test_unknown_event_blocked();
    std::cout << "All automaton tests passed.\n";
    return 0;
}
