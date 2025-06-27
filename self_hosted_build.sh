#!/usr/bin/env bash
set -eu
if [[ -z "${BOOTSTRAP_COMPILER:-}" ]]; then
    BOOTSTRAP_COMPILER=$HOME/bloat-buster-artifacts/releases/main/compiler_generic
fi

if [[ -z "${CMAKE_PREFIX_PATH:-}" ]]; then
    CMAKE_PREFIX_PATH=$HOME/dev/llvm/install/llvm_20.1.7_x86_64-linux-Release
fi

$BOOTSTRAP_COMPILER compile src/compiler.bbb
