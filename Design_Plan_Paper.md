# Design Plan: oMac-vsomeip (Paper-Specific Middleware-Level Integration)

This document tracks the paper-faithful branch work for the `paper-inheritance` line. The goal is to mirror the oMAC paper's secured SOME/IP message design: secured messages carry a 24-byte footer, standard messages remain unchanged, service discovery is untouched, and the reference monitor drops invalid messages before release to the application.

---

## 1. Paper Model

The paper's class diagram maps cleanly onto the public `vsomeip` API shape that is available in this environment:

```text
serializable / deserializable
          ^
          |
     message_base
          ^
          |
        message
```

The paper's `message_impl` sits in the internal implementation layer. The public headers we can compile against expose the abstract boundaries above, so the branch models the paper behavior in two ways:

1. Public runtime helpers that preserve the paper's wire format and monitor logic.
2. A mock inheritance proof that mirrors the paper's `SecuredMessageImpl` / `message_base` / `message` shape for documentation and tests.

---

## 2. Repository Reality

The public `vsomeip` headers available here expose `message_base` and `message` but not the concrete internal serializer/deserializer implementation needed to directly subclass the hidden runtime types. To keep the branch buildable while still matching the paper's wire format and policy behavior, the repository uses:

1. `SecuredPayload` helpers that produce and decode wire-format payloads with the 24-byte footer.
2. `SecuredMessage` wrappers that cache the verified application bytes and footer for monitor checks.
3. A reference-monitor gate in the example applications that drops unauthenticated or out-of-policy calls before forwarding.
4. A mock `SecuredMessageImpl` test artifact that demonstrates the inheritance-based footer logic the paper describes.

This keeps the runtime demo working with the public API while preserving the paper's footer semantics, CMAC verification, and state-automaton enforcement.

---

## 3. Paper-Specific Behaviors Implemented Here

### Footer Format

The footer remains the paper's 24-byte structure:

```cpp
#pragma pack(push, 1)
struct OMacFooter {
    uint32_t magic = 0x4F4D4143; // "OMAC"
    uint16_t domain_id;
    uint16_t method_id;
    uint8_t  mac[16];
};
#pragma pack(pop)
```

### Outbound Flow

1. Application bytes are collected.
2. The domain and method metadata are added to the CMAC input.
3. A 16-byte CMAC is computed.
4. The 24-byte footer is appended to the payload wire bytes.
5. The message is sent using standard SOME/IP payload APIs.

### Inbound Flow

1. The payload bytes are read from the message.
2. The footer is extracted from the tail.
3. The magic sentinel is checked.
4. The CMAC is verified.
5. The footer is stripped and the clean application bytes are passed to the monitor and service logic.

---

## 4. Paper Alignment Notes

The paper excerpt highlights three details that matter for this branch:

1. Secured messages inherit standard SOME/IP messages.
2. Service discovery messages are not modified.
3. Broker-forwarded calls use the `calling method` field to carry the forwarded method identifier.

The current branch reflects that behavior at the application boundary, while the mock inheritance proof keeps the paper's class hierarchy visible in the repo.

---

## 5. Remaining Work

1. If we want an even closer paper-figure proof, add a mock `message_base_impl`/`message_impl` harness under a dedicated `mock/` directory.
2. Keep the example applications using the wrapper helpers so the demo continues to build against public `vsomeip3`.
3. Preserve the public message paths for standard SOME/IP traffic and avoid changing service-discovery handling.
