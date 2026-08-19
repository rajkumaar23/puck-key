#!/usr/bin/env bash
# Build and run the host unit tests for the ESP32 Telegram-alerting core.
# Uses plain g++/clang - no Arduino toolchain or hardware needed.
set -euo pipefail
cd "$(dirname "$0")"

CXX="${CXX:-g++}"
FLAGS="-std=c++17 -Wall -Wextra -Werror -O2"

# 1. Main suite (each case calls reset() first - the normal happy path).
out=./notify_test
echo "Building $out with $CXX ..."
$CXX $FLAGS -o "$out" notify_test.cpp
echo "Running ..."
"$out"

# 2. Standalone fresh-boot regression. Its own process; calls alert() on the
#    shared st() with NO reset() first - exactly the firmware's first-boot
#    order. Guards against the tag table only being set by reset().
out2=./boot_state_regression
echo "Building $out2 with $CXX ..."
$CXX $FLAGS -o "$out2" boot_state_regression.cpp
echo "Running ..."
"$out2"

echo "ALL TESTS PASSED"
