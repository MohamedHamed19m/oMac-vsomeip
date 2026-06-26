#pragma once

#include "automaton.hpp"
#include "footer.hpp"

#include <mutex>
#include <string>
#include <unordered_map>

// ---------------------------------------------------------------------------
// ReferenceMonitor — the security gateway
//
// Lifecycle:
//   1. Constructed with a policy JSON path (passed to SimpleAutomaton).
//   2. On every incoming/outgoing message the application calls check().
//   3. check() verifies the CMAC tag, then asks the automaton whether the
//      (from, to, method) tuple is allowed in the current state.
//   4. Returns true → let the message through.
//      Returns false → drop / log violation.
//
// Thread safety: a std::mutex guards the automaton so vsomeip's worker
// threads cannot corrupt the state machine concurrently.
// ---------------------------------------------------------------------------

class ReferenceMonitor {
public:
    // Load policy from file.  Throws on error.
    explicit ReferenceMonitor(const std::string& policy_filepath);

    // Validate a raw vsomeip payload buffer that ends with an OMacFooter.
    //   payload_buf  — full buffer (application bytes + 24-byte footer)
    //   from_name    — resolved name of the sending component, e.g. "NAD::4G"
    //   to_name      — resolved name of the receiving component, e.g. "AppuP::RD"
    //   method_name  — human-readable method name, e.g. "invoke_RD"
    //
    // Returns true  → MAC valid AND state transition allowed.
    // Returns false → MAC invalid OR transition denied.
    bool check(const std::vector<uint8_t>& payload_buf,
               const std::string&          from_name,
               const std::string&          to_name,
               const std::string&          method_name);

    // Reset the automaton to its initial state (e.g. after a completed flow).
    void reset();

    // Current automaton state — useful for logging / debugging.
    std::string current_state() const;

private:
    SimpleAutomaton automaton_;
    mutable std::mutex mutex_;
};
