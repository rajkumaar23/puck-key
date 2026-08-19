#!/usr/bin/env bash
# Build and run the host unit tests for the ESP32 Telegram-alerting core.
# Uses plain g++/clang - no Arduino toolchain or hardware needed.
set -euo pipefail
cd "$(dirname "$0")"

CXX="${CXX:-g++}"
out=./notify_test
echo "Building $out with $CXX ..."
$CXX -std=c++17 -Wall -Wextra -Werror -O2 -o "$out" notify_test.cpp
echo "Running ..."
"$out"
