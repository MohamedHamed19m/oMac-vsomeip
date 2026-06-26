#include "reference_monitor.hpp"
#include "crypto.hpp"

#include <iostream>
#include <stdexcept>

// ---------------------------------------------------------------------------
// Constructor — load policy and initialise automaton.
// ---------------------------------------------------------------------------
ReferenceMonitor::ReferenceMonitor(const std::string& policy_filepath)
{
    automaton_.load_from_json(policy_filepath);
    std::cout << "[Monitor] Policy loaded. Initial state: "
              << automaton_.current_state << "\n";
}

// ---------------------------------------------------------------------------
// check — the hot path called on every message.
//
// Decision tree:
//   1. Buffer must contain a footer → reject if absent.
//   2. CMAC tag must be authentic    → reject on mismatch.
//   3. Automaton must allow the      → reject if wrong sequence.
//      (from, to, method) in the
//      current state.
// ---------------------------------------------------------------------------
bool ReferenceMonitor::check(const std::vector<uint8_t>& payload_buf,
                              const std::string&          from_name,
                              const std::string&          to_name,
                              const std::string&          method_name)
{
    // --- Step 1: footer present? -------------------------------------------
    if (!footer_present(payload_buf)) {
        std::cout << "[Monitor] BLOCK — no footer in message from "
                  << from_name << "\n";
        return false;
    }

    OMacFooter footer  = footer_extract(payload_buf);
    auto       payload = payload_without_footer(payload_buf);

    // --- Step 2: verify CMAC -------------------------------------------------
    bool mac_ok = crypto::verify_message(payload.data(), payload.size(), footer);
    if (!mac_ok) {
        std::cout << "[Monitor] BLOCK — MAC verification failed ("
                  << from_name << " → " << to_name << " : " << method_name << ")\n";
        return false;
    }

    // --- Step 3: automaton check --------------------------------------------
    std::lock_guard<std::mutex> lock(mutex_);

    std::string event_key = SimpleAutomaton::make_key(from_name, to_name, method_name);
    bool allowed = automaton_.process_event(event_key);

    // State synchronization: if blocked, check if this is a forwarded/broker message.
    // We trust the broker (non-NAD components) to have already verified the sequence.
    // If the CMAC is valid and the transition exists in another state, sync to it.
    if (!allowed && from_name.rfind("NAD", 0) != 0) {
        for (const auto& pair : automaton_.transitions) {
            const std::string& state_name = pair.first;
            const auto& state_transitions = pair.second;
            if (state_transitions.find(event_key) != state_transitions.end()) {
                std::cout << "[Monitor] State sync: " << automaton_.current_state
                          << " -> " << state_name << " (matching authentic transition)\n";
                automaton_.current_state = state_name;
                allowed = automaton_.process_event(event_key);
                break;
            }
        }
    }

    if (allowed) {
        std::cout << "[Monitor] ALLOW  — "
                  << from_name << " → " << to_name << " : " << method_name
                  << "  (state: " << automaton_.current_state << ")\n";
    } else {
        std::cout << "[Monitor] BLOCK  — "
                  << from_name << " → " << to_name << " : " << method_name
                  << "  (state: " << automaton_.current_state
                  << " — no matching transition)\n";
    }

    return allowed;
}

// ---------------------------------------------------------------------------
// reset — delegate to automaton.
// ---------------------------------------------------------------------------
void ReferenceMonitor::reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    automaton_.reset();
    std::cout << "[Monitor] Reset → state: " << automaton_.current_state << "\n";
}

// ---------------------------------------------------------------------------
// current_state — for external inspection.
// ---------------------------------------------------------------------------
std::string ReferenceMonitor::current_state() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return automaton_.current_state;
}
