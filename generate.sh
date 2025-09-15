#!/usr/bin/env bash
set -eux

if [[ -z "${LLVM_VERSION:-}" ]]; then
    LLVM_VERSION=21.1.1
fi

if [[ -z "${BB_CI:-}" ]]; then
    BB_CI=0
fi

if [[ -z "${CMAKE_BUILD_TYPE:-}" ]]; then
    CMAKE_BUILD_TYPE=Debug
    LLVM_CMAKE_BUILD_TYPE=Release
elif [[ -z "${LLVM_CMAKE_BUILD_TYPE:-}" ]]; then
    LLVM_CMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE
fi

BIRTH_NATIVE_OS_STRING=$OSTYPE

case "$BIRTH_NATIVE_OS_STRING" in
    darwin*) BIRTH_OS="macos";;
    linux*) BIRTH_OS="linux";;
    msys*) BIRTH_OS="windows";;
    *) exit 1
esac

BIRTH_NATIVE_ARCH_STRING="$(uname -m)"

case "$BIRTH_NATIVE_ARCH_STRING" in
    x86_64) BIRTH_ARCH="x86_64";;
    arm64) BIRTH_ARCH="aarch64";;
    *) exit 1
esac

if [[ -z "${CMAKE_PREFIX_PATH:-}" ]]; then
    CMAKE_PREFIX_PATH=$HOME/dev/llvm/install/llvm_${LLVM_VERSION}_${BIRTH_ARCH}-${BIRTH_OS}-${LLVM_CMAKE_BUILD_TYPE}
fi

if [[ -z "${CLANG_PATH:-}" ]]; then
    CLANG_PATH=clang
    CLANGXX_PATH=clang++
fi

OPT_ARGS=""

case "${CMAKE_BUILD_TYPE%%-*}" in
    Debug) OPT_ARGS="-O0 -g";;
    Release*) OPT_ARGS="-O3";;
    RelWithDebInfo*) OPT_ARGS="-O2 -g";;
    *) exit 1;;
esac

case "$BIRTH_OS" in
    linux) CMAKE_LINKER_TYPE=MOLD;;
    *) CMAKE_LINKER_TYPE=DEFAULT;;
esac

if [[ -z "${BB_CACHE_DIR:-}" ]]; then
    BB_CACHE_DIR=bb-cache
fi

mkdir -p $BB_CACHE_DIR
#$CLANG_PATH -c tests/c_abi.c -o $BB_CACHE_DIR/c_abi_generic.o $OPT_ARGS -std=gnu2x
#$CLANG_PATH -c tests/c_abi.c -o $BB_CACHE_DIR/c_abi_native.o $OPT_ARGS -std=gnu2x -march=native

rm -rf build || true
mkdir -p build
cd build
cmake --log-level=VERBOSE .. -G Ninja -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE -DCMAKE_CXX_COMPILER=$CLANGXX_PATH -DCMAKE_C_COMPILER=$CLANG_PATH -DCMAKE_LINKER_TYPE=$CMAKE_LINKER_TYPE -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_COLOR_DIAGNOSTICS=ON -DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}
cd ..
