# oMac-vsomeip

A secure SOME/IP reference monitor proof-of-concept implementing state-aware access control using CMAC (AES-128-CMAC) security footers.

## Features

- **Secured Message Composition**: Wraps standard `vsomeip` messages with a backward-compatible 24-byte secured footer.
- **CMAC Authentication**: Uses OpenSSL to calculate and verify AES-128-CMAC codes for message integrity.
- **Automaton State Machine**: Evaluates transition policies based on calling method and domain IDs.
- **Reference Monitor**: Integrates the state machine and crypto verification to guard services in real-time.

## Prerequisites (WSL / Linux)

1. **vsomeip3**: Ensure vsomeip3 is installed (already present in `/usr/local` on your system).
2. **OpenSSL Development Headers**:
   ```bash
   sudo apt update
   sudo apt install -y libssl-dev cmake build-essential
   ```

## Building

Build the project from WSL (you can run this directly in the `/mnt/c` mount directory):

```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

## Running Tests

From the `build/` directory:

```bash
ctest --output-on-failure
```

## Running the vsomeip Examples

To run the vsomeip simulation, open 3 WSL terminals:

### Terminal 1 (Safety Controller Service / Server)
```bash
cd build/examples
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-safety.json ./safety_uc ../../policies/tcu_rd_rc_policy.json
```

### Terminal 2 (App-Up Client / Middleman)
```bash
cd build/examples
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-appup.json ./app_up ../../policies/tcu_rd_rc_policy.json
```

### Terminal 3 (NAD App Client)
```bash
cd build/examples
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-nad.json ./nad_app
```
