# oMac-vsomeip: Build and Run Guide

This guide covers WSL build, test, and demo commands for the current branch. If you want a single entrypoint, run `./run_demo.sh` from the repository root in WSL.

---

## 1. Prerequisites

Use WSL / Ubuntu with the usual build tools and OpenSSL development headers installed.

---

## 2. Build

From a WSL shell:

```bash
cd /mnt/c/Users/user/Desktop/test/0_my_repo/oMac-vsomeip
mkdir -p build
cd build
cmake ..
cmake --build . -j4
```

This builds:
- `libomac.a`
- `test_footer`, `test_crypto`, `test_automaton`, `test_flows`, and `test_inheritance`
- `nad_app`, `app_up`, and `safety_uc`

---

## 3. Test

Run the full test suite from `build/`:

```bash
cd /mnt/c/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/build
ctest --output-on-failure
```

Expected result:
- 5 tests pass
- Includes the new `inheritance` mock-proof test

---

## 4. Demo Setup

Open 3 WSL terminals and run the commands below in `build/examples`.

First enter the examples directory:

```bash
cd /mnt/c/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/build/examples
```

### Terminal 1: Safety controller

```bash
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-safety.json ./safety_uc ../../policies/tcu_rd_rc_policy.json
```

### Terminal 2: App UP broker

```bash
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-appup.json ./app_up ../../policies/tcu_rd_rc_policy.json
```

### Terminal 3: NAD client

```bash
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-nad.json ./nad_app
```

---

## 5. What To Expect

- `nad_app` sends the scripted F1 to F5 sequence.
- `app_up` allows the valid call, blocks the out-of-sequence and invalid messages, and forwards the accepted call.
- `safety_uc` receives the forwarded diagnostic call and executes it after CMAC and policy checks.
- The demo ends cleanly after the client finishes its sequence.
