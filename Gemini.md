# oMac-vsomeip: Build & Run Guide

This guide provides step-by-step instructions for compiling the project, executing unit/integration tests, and running the `vsomeip` multi-process simulation.

---

## 1. Prerequisites (WSL / Ubuntu)

Before building, install the OpenSSL development headers and essential build tools in your WSL distribution:

```bash
sudo apt update
sudo apt install -y libssl-dev cmake build-essential
```

*Note: `vsomeip3` is already pre-installed under `/usr/local` on your environment.*

---

## 2. Compiling the Project

Navigate to the project root directory inside your WSL terminal and run:

```bash
cd /mnt/c/Users/user/Desktop/test/0_my_repo/oMac-vsomeip
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

This compiles:
- `libomac.a`: Core static library (crypto, automaton, reference monitor).
- Test executables under `build/tests/`.
- Example nodes (`nad_app`, `app_up`, `safety_uc`) under `build/examples/`.

---

## 3. Running the Test Suite

From your `build/` directory, run CTest to verify all unit and integration tests pass:

```bash
ctest --output-on-failure
```

Expected output:
```text
Test project /mnt/c/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/build
    Start 1: footer
1/4 Test #1: footer ...........................   Passed    0.00 sec
    Start 2: crypto
2/4 Test #2: crypto ...........................   Passed    0.01 sec
    Start 3: automaton
3/4 Test #3: automaton ........................   Passed    0.01 sec
    Start 4: flows
4/4 Test #4: flows ............................   Passed    0.01 sec

100% tests passed, 0 tests failed out of 4
```

---

## 4. Running the Multi-Process vsomeip Demo

To run the simulation, open **3 separate WSL terminal windows** and navigate to the `build/examples` directory in each:

```bash
cd /mnt/c/Users/user/Desktop/test/0_my_repo/oMac-vsomeip/build/examples
```

### Terminal 1: Safety Controller Service (Server)
Start the protected server node first so it can claim the `vsomeip` routing manager socket:

```bash
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-safety.json ./safety_uc ../../policies/tcu_rd_rc_policy.json
```

### Terminal 2: App µP Broker (Forwarder / Router)
Start the broker next. It will connect to the routing manager and request downstream services from `safety_uc`:

```bash
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-appup.json ./app_up ../../policies/tcu_rd_rc_policy.json
```

### Terminal 3: NAD Application (Client)
Start the client application. It will send a sequence of legitimate flows (F1, F2) and simulated attacks (F3, F4, invalid footers):

```bash
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-nad.json ./nad_app
```

---

## 5. What to Observe in the Demo Output

### Legitimate Flows
1. **Flow F1 (Diagnostic session initiation followed by forwarded Diag call):**
   - **`nad_app`** sends `invoke_RD`.
   - **`app_up`** receives `invoke_RD` and its monitor transitions state: `idle -> nad_called_rd` (ALLOW).
   - **`app_up`** forwards the call `invoke_Diag` to `safety_uc`.
   - **`safety_uc`** receives `invoke_Diag`, verifies the CMAC, automatically synchronizes its state to `nad_called_rd`, processes the event, and transitions to `idle` (ALLOW).
2. **Flow F2 (Remote Control session initiation followed by forwarded Ctrl call):**
   - Follows the same pattern as F1, transitioning states: `idle -> nad_called_rc -> idle` (ALLOW).

### Attack Flows
1. **Out-of-Sequence Call (RC call twice in a row):**
   - **`nad_app`** attempts `invoke_RC` while the system is already in the `nad_called_rd` state.
   - **`app_up`**'s monitor checks the transition and rejects it (BLOCK - state unchanged).
2. **Unauthorized Component (GPS interface):**
   - **`nad_app`** tries to spoof a command as `NAD::GPS`.
   - **`app_up`**'s monitor rejects the command (BLOCK).
3. **Payload / Footer Tampering:**
   - **`nad_app`** sends a message with a missing or manipulated footer.
   - The monitor detects the mismatch in the CMAC verification and immediately discards the packet (BLOCK).
