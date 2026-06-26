# oMac-vsomeip

A secure SOME/IP reference monitor proof-of-concept implementing state-aware access control using CMAC (AES-128-CMAC) security footers. This project is a simplified Minimum Viable Product (MVP) design showing how stateful security policies can be dynamically enforced on top of `vsomeip` middleware in a C++17 environment.

For quick instructions on setting up, building, and running the simulation, refer to the [Build & Run Guide (Gemini.md)](file:///C:/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/Gemini.md).

---

## 📖 Architectural Design

We have implemented a clean, flat C++17 architecture to maximize focus on the core security thesis of the oMac paper:

```
omac-vsomeip/
├── CMakeLists.txt                  # Build configuration
├── README.md                       # High-level overview
├── Gemini.md                       # Build & Run guide
│
├── include/
│   ├── footer.hpp                  # 24-byte OMacFooter struct
│   ├── crypto.hpp                  # CMAC sign/verify utilities
│   ├── automaton.hpp               # State transition machine
│   └── reference_monitor.hpp       # ReferenceMonitor interceptor
│
├── src/
│   ├── crypto.cpp                  # OpenSSL AES-128-CMAC implementation
│   ├── automaton.cpp               # JSON policy loading and matching
│   └── reference_monitor.cpp       # Interception & state verification
│
├── policies/
│   └── tcu_rd_rc_policy.json       # TCU example transitions (RD + RC flows)
│
├── examples/                       # vsomeip simulation nodes
│   ├── nad_app.cpp                 # Client node (NAD simulator)
│   ├── app_up.cpp                  # Gateway/Router broker (App µP simulator)
│   └── safety_uc.cpp               # Protected endpoint (Safety µC simulator)
│
└── tests/                          # CTest suite
    ├── test_footer.cpp             # Footer data layout tests
    ├── test_crypto.cpp             # CMAC signing/verification tests
    ├── test_automaton.cpp          # State transition logic tests
    └── test_flows.cpp              # Integration flow checks (F1-F4)
```

---

## 🔒 Security Components

### 1. The Security Footer (`OMacFooter`)
Defined in [include/footer.hpp](file:///C:/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/include/footer.hpp), it is a packed 24-byte struct appended to the end of every SOME/IP message:
```cpp
#pragma pack(push, 1)
struct OMacFooter {
    uint32_t magic = 0x4F4D4143; // "OMAC"
    uint16_t domain_id;          // Sender's functional domain
    uint16_t method_id;          // Triggering calling method
    uint8_t  mac[16];            // CMAC authentication tag
};
#pragma pack(pop)
```
Legacy nodes that are not oMac-aware simply read the standard payload length and ignore the trailing 24 bytes, maintaining backward compatibility.

### 2. Standalone Cryptography
Located in [src/crypto.cpp](file:///C:/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/src/crypto.cpp), it utilizes OpenSSL to generate and verify AES-128-CMAC signatures. The MAC input contains the application payload + the `domain_id` + `method_id`, preventing message parameter swapping or replay attacks under different contexts.

### 3. State-Aware Automaton
Located in [src/automaton.cpp](file:///C:/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/src/automaton.cpp), it reads JSON policies and models the allowed transitions. Key transitions are identified using the format:
```text
from_component::to_component::method
```

### 4. Distributed State Synchronization
Because each process (e.g. `app_up` vs `safety_uc`) runs its own reference monitor instance, state machines are naturally isolated. Since `safety_uc` only witnesses the forwarded message and not the initial NAD handshake, it would normally block legitimate diagnostic/control commands due to state mismatch.

To solve this, the [ReferenceMonitor](file:///C:/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/src/reference_monitor.cpp) implements a secure **State Synchronization** mechanism:
* **Strict Sequences:** For client messages coming directly from the client network (sender starting with `"NAD"`), the monitor strictly checks the current local state machine sequence. No synchronization is allowed.
* **Authentic Broker Forwarding:** For forwarded messages coming from trusted broker components (sender not starting with `"NAD"`), the receiver validates the cryptographic CMAC. If valid, the receiver trusts the broker's monitor to have checked the sequence and automatically synchronizes its local state machine to match the expected state of the transition, allowing the call.
