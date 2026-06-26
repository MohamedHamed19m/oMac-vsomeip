# oMac-vsomeip

A secure SOME/IP reference-monitor proof of concept implementing state-aware access control with CMAC (AES-128-CMAC) security footers.

The current branch keeps the runtime demo buildable against the public `vsomeip3` API while preserving the paper's wire-format behavior and state-automaton enforcement. It also includes a mock inheritance test that mirrors the paper's `SecuredMessageImpl` idea.

For build, test, and demo commands, see [Gemini.md](file:///C:/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/Gemini.md). For a one-file WSL entrypoint, use `run_demo.sh` from the repository root.

---

## Repository Layout

- `include/`: footer, crypto, monitor, and secured-message helpers
- `src/`: CMAC, automaton, and reference-monitor implementation
- `examples/`: `nad_app`, `app_up`, and `safety_uc`
- `tests/`: footer, crypto, automaton, flow, and inheritance tests
- `policies/`: sample TCU policy
- `run_demo.sh`: one-file WSL build, test, and demo wrapper
- `build/`: generated build tree

---

## Current Behavior

- The 24-byte `OMacFooter` is appended to message payloads.
- `ReferenceMonitor` validates the footer and CMAC before allowing a transition.
- Broker-forwarded messages keep working with the same call semantics used by the paper.
- The example applications are guarded by the monitor before forwarding or execution.

---

## Verification Status

- Build: passes in WSL
- Tests: `ctest` passes 5 tests
- Demo: `safety_uc`, `app_up`, and `nad_app` run end-to-end in WSL
- One-file wrapper: `run_demo.sh` builds, tests, and runs the demo in WSL

---

## Notes

- The source tree includes a mock inheritance proof for the paper-specific `SecuredMessageImpl` model.
- The demo uses the public `vsomeip` API and does not depend on hidden internal serializer/deserializer types.
