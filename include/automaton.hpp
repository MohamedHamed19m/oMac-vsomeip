#pragma once

#include <string>
#include <unordered_map>

// ---------------------------------------------------------------------------
// SimpleAutomaton — string-based state machine
//
// States and events are plain std::string values, which keeps the code
// readable and the policy JSON directly understandable.
//
// Transition key format: "from_component::to_component::method"
//   e.g. "NAD::4G::AppuP::RD::invoke_RD"
//
// A transition table entry maps:
//   transitions[current_state][event_key] = next_state
//
// If the event is not found in the current state's map:
//   - default_action == true  → allowed (open system)
//   - default_action == false → denied  (closed system — our default)
// ---------------------------------------------------------------------------

class SimpleAutomaton {
public:
    SimpleAutomaton() = default;

    // Transition table: state → (event_key → next_state)
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::string>> transitions;

    std::string current_state = "idle";
    bool        default_action = false;   // deny-by-default

    // Load state and transitions from a JSON policy file.
    // Throws std::runtime_error on parse / IO error.
    void load_from_json(const std::string& filepath);

    // Reset the automaton to its initial state.
    void reset();

    // Process an event.
    // Returns true  → transition found, state advanced, call is ALLOWED.
    // Returns false → no transition found, call is BLOCKED (default_action=false).
    bool process_event(const std::string& event_key);

    // Build a canonical event key from its three components.
    static std::string make_key(const std::string& from,
                                const std::string& to,
                                const std::string& method);

private:
    std::string initial_state_ = "idle";
};
