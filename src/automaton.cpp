#include "automaton.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// make_key — produces a canonical event identifier string.
// Format: "from_component::to_component::method"
// ---------------------------------------------------------------------------
std::string SimpleAutomaton::make_key(const std::string& from,
                                      const std::string& to,
                                      const std::string& method)
{
    return from + "::" + to + "::" + method;
}

// ---------------------------------------------------------------------------
// load_from_json — read a policy file and populate the transition table.
//
// Expected JSON schema (see policies/tcu_rd_rc_policy.json):
// {
//   "name":          "...",
//   "initial_state": "idle",
//   "default":       "deny",          // "allow" | "deny"
//   "transitions": [
//     {
//       "from_state":     "idle",
//       "from_component": "NAD::4G",
//       "to_component":   "AppuP::RD",
//       "method":         "invoke_RD",
//       "to_state":       "nad_called_rd",
//       "allow":          true
//     }, ...
//   ]
// }
// ---------------------------------------------------------------------------
void SimpleAutomaton::load_from_json(const std::string& filepath)
{
    std::ifstream f(filepath);
    if (!f.is_open())
        throw std::runtime_error("Cannot open policy file: " + filepath);

    json j;
    try {
        j = json::parse(f);
    } catch (const json::parse_error& e) {
        throw std::runtime_error("JSON parse error in " + filepath + ": " + e.what());
    }

    // Read initial state
    if (!j.contains("initial_state"))
        throw std::runtime_error("Policy missing 'initial_state': " + filepath);
    initial_state_ = j["initial_state"].get<std::string>();
    current_state  = initial_state_;

    // Read default action
    std::string def = j.value("default", "deny");
    default_action  = (def == "allow");

    // Read transitions
    if (!j.contains("transitions") || !j["transitions"].is_array())
        throw std::runtime_error("Policy missing 'transitions' array: " + filepath);

    transitions.clear();
    for (const auto& t : j["transitions"]) {
        // Only load transitions explicitly marked allow:true
        // deny entries in the JSON are informational — the automaton denies
        // by default for anything not in the table.
        if (!t.value("allow", false)) continue;

        std::string from_state = t.at("from_state").get<std::string>();
        std::string key = make_key(
            t.at("from_component").get<std::string>(),
            t.at("to_component").get<std::string>(),
            t.at("method").get<std::string>()
        );
        std::string to_state = t.at("to_state").get<std::string>();

        transitions[from_state][key] = to_state;
    }
}

// ---------------------------------------------------------------------------
// reset — return to the initial state (used after a complete flow or error).
// ---------------------------------------------------------------------------
void SimpleAutomaton::reset()
{
    current_state = initial_state_;
}

// ---------------------------------------------------------------------------
// process_event — look up the event in the current state's transition map.
// Advances state on a hit, leaves state unchanged on a miss.
// ---------------------------------------------------------------------------
bool SimpleAutomaton::process_event(const std::string& event_key)
{
    auto state_it = transitions.find(current_state);
    if (state_it != transitions.end()) {
        auto event_it = state_it->second.find(event_key);
        if (event_it != state_it->second.end()) {
            current_state = event_it->second;  // advance state
            return true;                        // ALLOWED
        }
    }
    return default_action;  // BLOCKED (false by default)
}
