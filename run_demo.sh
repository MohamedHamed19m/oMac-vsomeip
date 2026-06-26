#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/build"
EXAMPLES_DIR="$BUILD_DIR/examples"
LOG_DIR="/tmp/omac-vsomeip-demo-$$"
SAFETY_LOG="$LOG_DIR/safety_uc.log"
APPUP_LOG="$LOG_DIR/app_up.log"
NAD_LOG="$LOG_DIR/nad_app.log"

mkdir -p "$LOG_DIR"

cleanup() {
  local exit_code=$?
  if [[ -n "${NAD_PID:-}" ]] && kill -0 "$NAD_PID" 2>/dev/null; then
    kill "$NAD_PID" 2>/dev/null || true
  fi
  if [[ -n "${APPUP_PID:-}" ]] && kill -0 "$APPUP_PID" 2>/dev/null; then
    kill "$APPUP_PID" 2>/dev/null || true
  fi
  if [[ -n "${SAFETY_PID:-}" ]] && kill -0 "$SAFETY_PID" 2>/dev/null; then
    kill "$SAFETY_PID" 2>/dev/null || true
  fi
  wait "${NAD_PID:-}" 2>/dev/null || true
  wait "${APPUP_PID:-}" 2>/dev/null || true
  wait "${SAFETY_PID:-}" 2>/dev/null || true
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

echo "[1/4] Configuring and building"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake ..
cmake --build . -j4

echo "[2/4] Running tests"
ctest --output-on-failure

echo "[3/4] Starting demo processes"
cd "$EXAMPLES_DIR"
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-safety.json ./safety_uc ../../policies/tcu_rd_rc_policy.json > "$SAFETY_LOG" 2>&1 &
SAFETY_PID=$!
sleep 2
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-appup.json ./app_up ../../policies/tcu_rd_rc_policy.json > "$APPUP_LOG" 2>&1 &
APPUP_PID=$!
sleep 3
VSOMEIP_CONFIGURATION=../../examples/config/vsomeip-nad.json ./nad_app > "$NAD_LOG" 2>&1 &
NAD_PID=$!
wait "$NAD_PID"
sleep 2
kill "$APPUP_PID" "$SAFETY_PID" 2>/dev/null || true
wait "$APPUP_PID" "$SAFETY_PID" 2>/dev/null || true

echo "[4/4] Demo logs"
echo "=== safety_uc ==="
cat "$SAFETY_LOG"
echo "=== app_up ==="
cat "$APPUP_LOG"
echo "=== nad_app ==="
cat "$NAD_LOG"